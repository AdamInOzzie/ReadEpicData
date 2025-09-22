#!/usr/bin/env bash
set -euo pipefail

# Run the SMART on FHIR demo with provided env vars.
# Fetches CLIENT_ID and FHIR_BASE_URL automatically from:
#  1) CLI args (highest precedence)
#  2) Env vars (CLIENT_ID / NONPROD_CLIENT_ID, FHIR_BASE_URL / NONPROD_FHIR_BASE_URL)
#  3) macOS Keychain (service: ReadEpicData, accounts: prod_client_id, nonprod_client_id, prod_fhir_base_url, nonprod_fhir_base_url)
#  4) ./.client_ids file (PROD_CLIENT_ID=..., NONPROD_CLIENT_ID=..., PROD_FHIR_BASE_URL=..., NONPROD_FHIR_BASE_URL=...)
#  5) Prompt if still missing
# Usage:
#   ./run.sh [--nonprod] [CLIENT_ID] [FHIR_BASE_URL] [REDIRECT_URI] [SCOPES]
# Or simply:
#   ./run.sh              # uses stored production values
#   ./run.sh --nonprod    # uses stored non-production values

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SERVICE="ReadEpicData"

# Provide safe defaults for optional TLS vars so set -u doesn't fail
CERT_FILE="${CERT_FILE:-}"
KEY_FILE="${KEY_FILE:-}"
# Default port if not provided via environment
PORT_VALUE="${PORT:-8765}"

kc_get() {
  # $1 account name
  local account="$1"
  security find-generic-password -s "$SERVICE" -a "$account" -w 2>/dev/null || true
}

file_get() {
  # $1 var name, reads from .client_ids if present
  local var="$1"
  if [[ -f .client_ids ]]; then
    # shellcheck disable=SC1090
    source .client_ids
    eval "echo \"\${$var:-}\""
  fi
}

prompt_if_empty() {
  # $1 varname, $2 prompt
  local __varname="$1"
  local __prompt="$2"
  local __value="${!__varname:-}"
  if [[ -z "$__value" ]]; then
    read -r -p "$__prompt: " __value
    eval "$__varname=\"$__value\""
  fi
}

MODE="prod"
HTTPS_FLAG="0"
if [[ "${1:-}" == "--nonprod" || "${1:-}" == "-n" ]]; then
  MODE="nonprod"
  shift
fi
if [[ "${1:-}" == "--https" ]]; then
  HTTPS_FLAG="1"
  shift
fi

# Resolve inputs by mode with cascading fallbacks
if [[ "$MODE" == "nonprod" ]]; then
  CLIENT_ID_INPUT="${1:-${NONPROD_CLIENT_ID:-$(kc_get nonprod_client_id)}}"
  FHIR_BASE_URL_INPUT="${2:-${NONPROD_FHIR_BASE_URL:-$(kc_get nonprod_fhir_base_url)}}"
else
  CLIENT_ID_INPUT="${1:-${CLIENT_ID:-$(kc_get prod_client_id)}}"
  FHIR_BASE_URL_INPUT="${2:-${FHIR_BASE_URL:-$(kc_get prod_fhir_base_url)}}"
fi

# Fallback to .client_ids file
if [[ -z "$CLIENT_ID_INPUT" ]]; then
  if [[ "$MODE" == "nonprod" ]]; then
    CLIENT_ID_INPUT="$(file_get NONPROD_CLIENT_ID)"
  else
    CLIENT_ID_INPUT="$(file_get PROD_CLIENT_ID)"
  fi
fi
if [[ -z "$FHIR_BASE_URL_INPUT" ]]; then
  if [[ "$MODE" == "nonprod" ]]; then
    FHIR_BASE_URL_INPUT="$(file_get NONPROD_FHIR_BASE_URL)"
  else
    FHIR_BASE_URL_INPUT="$(file_get PROD_FHIR_BASE_URL)"
  fi
fi

# Default redirect depending on HTTPS flag
DEFAULT_REDIRECT="http://127.0.0.1:8765/callback"
if [[ "$HTTPS_FLAG" == "1" ]]; then
  DEFAULT_REDIRECT="https://127.0.0.1:8765/callback"
fi
REDIRECT_URI_INPUT="${3:-${REDIRECT_URI:-$DEFAULT_REDIRECT}}"
SCOPES_INPUT="${4:-${SCOPES:-"openid fhirUser launch/patient patient/*.read offline_access"}}"

# Interactive prompt as last resort
if [[ -z "$CLIENT_ID_INPUT" ]]; then
  if [[ "$MODE" == "nonprod" ]]; then
    prompt_if_empty CLIENT_ID_INPUT "Enter Non-Production Client ID"
  else
    prompt_if_empty CLIENT_ID_INPUT "Enter Production Client ID"
  fi
fi
if [[ -z "$FHIR_BASE_URL_INPUT" ]]; then
  if [[ "$MODE" == "nonprod" ]]; then
    prompt_if_empty FHIR_BASE_URL_INPUT "Enter Non-Production FHIR Base URL"
  else
    prompt_if_empty FHIR_BASE_URL_INPUT "Enter UCSF (Production) FHIR Base URL"
  fi
fi

# Validate
if [[ -z "$CLIENT_ID_INPUT" || -z "$FHIR_BASE_URL_INPUT" ]]; then
  echo "Missing CLIENT_ID or FHIR_BASE_URL. Provide via args, env, keychain, .client_ids, or prompt." >&2
  exit 1
fi

# Export chosen values so all subsequent steps see them
export CLIENT_ID="$CLIENT_ID_INPUT"
export FHIR_BASE_URL="$FHIR_BASE_URL_INPUT"
export REDIRECT_URI="$REDIRECT_URI_INPUT"
export SCOPES="$SCOPES_INPUT"
export MODE
export HTTPS="$HTTPS_FLAG"
export CERT_FILE
export KEY_FILE

# Persist to .env for python-dotenv consumers
cat > .env <<EOF
CLIENT_ID=$CLIENT_ID
FHIR_BASE_URL=$FHIR_BASE_URL
REDIRECT_URI=$REDIRECT_URI
SCOPES="$SCOPES"
PORT=$PORT_VALUE
HTTPS=$HTTPS
CERT_FILE=$CERT_FILE
KEY_FILE=$KEY_FILE
EOF

if [[ "$MODE" == "nonprod" ]]; then
  echo "Mode: Non-Production (Epic sandbox)"
else
  echo "Mode: Production (UCSF)"
fi

echo "CLIENT_ID=$CLIENT_ID"
echo "FHIR_BASE_URL=$FHIR_BASE_URL"
echo "REDIRECT_URI=$REDIRECT_URI"
echo "SCOPES=$SCOPES"
echo "PORT=$PORT_VALUE"
if [[ "$HTTPS_FLAG" == "1" ]]; then
  echo "HTTPS=enabled (self-signed if no CERT_FILE/KEY_FILE provided)"
fi

# Create venv if missing and install deps
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -r requirements.txt >/dev/null

# Run the app
exec python app.py
