import json
import os
import secrets
import string

from dataclasses import dataclass
from typing import Dict, Optional

import requests
from flask import Flask, jsonify, redirect, request, send_from_directory
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
FHIR_BASE_URL = os.getenv("FHIR_BASE_URL")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://127.0.0.1:8765/callback")
SCOPES = os.getenv("SCOPES", "openid fhirUser launch/patient patient/*.read offline_access")
# Robust PORT parsing: handle empty string
_port_env = os.getenv("PORT") or "8765"
PORT = int(_port_env)
EXPORT_DIR = os.getenv("EXPORT_DIR", os.path.join(os.getcwd(), "exports"))

app = Flask(__name__)

tokens_path = os.path.join(os.getcwd(), 'tokens.json')


def random_string(n=64):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(n))


@dataclass
class OAuthConfig:
    authorize_url: str
    token_url: str
    userinfo_url: Optional[str] = None


def smart_discover(fhir_base: str) -> OAuthConfig:
    base = fhir_base.rstrip('/')
    # Try SMART well-known URL first
    well_known = f"{base}/.well-known/smart-configuration"
    try:
        r = requests.get(well_known, headers={"Accept": "application/json"}, timeout=15)
        if r.ok:
            data = r.json()
            return OAuthConfig(
                authorize_url=data["authorization_endpoint"],
                token_url=data["token_endpoint"],
                userinfo_url=data.get("userinfo_endpoint"),
            )
    except Exception:
        # ignore and try other strategies
        pass

    # If Epic sandbox/org pattern, derive oauth2 endpoints directly
    if ('fhir.epic.com' in base) or ('interconnect-fhir-oauth' in base):
        # Example: https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4 -> root https://fhir.epic.com/interconnect-fhir-oauth
        root = base.split('/api/')[0].rstrip('/')
        return OAuthConfig(
            authorize_url=f"{root}/oauth2/authorize",
            token_url=f"{root}/oauth2/token",
            userinfo_url=f"{root}/oauth2/userinfo",
        )

    # Fallback to metadata CapabilityStatement
    meta = f"{base}/metadata"
    r = requests.get(meta, headers={"Accept": "application/json"}, timeout=15)
    r.raise_for_status()
    cs = r.json()
    # Navigate security extensions to find OAuth URLs
    rest = cs.get('rest', [])
    for rrest in rest:
        sec = rrest.get('security', {})
        ext = sec.get('extension', [])
        for e in ext:
            if e.get('url', '').endswith('oauth-uris'):
                authz = None
                token = None
                userinfo = None
                for uri in e.get('extension', []):
                    if uri.get('url') == 'authorize':
                        authz = uri.get('valueUri')
                    if uri.get('url') == 'token':
                        token = uri.get('valueUri')
                    if uri.get('url') == 'userinfo':
                        userinfo = uri.get('valueUri')
                if authz and token:
                    return OAuthConfig(authorize_url=authz, token_url=token, userinfo_url=userinfo)
    raise RuntimeError('Could not discover SMART OAuth endpoints from FHIR base URL')


def save_tokens(tok: Dict):
    with open(tokens_path, 'w') as f:
        json.dump(tok, f, indent=2)


def load_tokens() -> Optional[Dict]:
    if not os.path.exists(tokens_path):
        return None
    with open(tokens_path) as f:
        return json.load(f)


oauth_config: Optional[OAuthConfig] = None
client: Optional[OAuth2Session] = None
code_verifier = None
state_param = None

@app.route('/')
def index():
    return jsonify({
        'status': 'ok',
        'instructions': 'Go to /login to start UCSF MyChart login via SMART on FHIR',
    })

@app.route('/login')
def login():
    global oauth_config, client, code_verifier, state_param
    assert CLIENT_ID and FHIR_BASE_URL, "Set CLIENT_ID and FHIR_BASE_URL in .env"

    try:
        oauth_config = smart_discover(FHIR_BASE_URL)
    except Exception as e:
        # Return a friendly error instead of a 500 when discovery fails (e.g., sandbox outage)
        return jsonify({
            'error': 'SMART discovery failed',
            'fhir_base_url': FHIR_BASE_URL,
            'details': str(e),
            'hint': 'If using Epic sandbox, this may be a temporary outage. Retry later or switch to production.'
        }), 503

    # PKCE setup
    code_verifier = random_string(64)
    # RFC 7636 S256 method
    from hashlib import sha256
    import base64
    code_challenge = base64.urlsafe_b64encode(sha256(code_verifier.encode()).digest()).decode().rstrip('=')

    client = OAuth2Session(
        CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope=SCOPES.split()
    )

    # Allow omitting aud for servers that reject it (set OMIT_AUD=1)
    params = {
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }
    if (os.getenv('OMIT_AUD', '').lower() not in ('1', 'true', 'yes')):
        params['aud'] = FHIR_BASE_URL

    authorization_url, state_param = client.authorization_url(
        oauth_config.authorize_url,
        **params
    )

    # Log built URL for troubleshooting
    try:
        print(f"[login] authorize_url={authorization_url}")
    except Exception:
        pass

    return redirect(authorization_url)

@app.route('/callback')
def callback():
    global oauth_config, client, code_verifier

    if oauth_config is None or client is None:
        return jsonify({'error': 'OAuth session missing. Start at /login'}), 400

    if 'error' in request.args:
        return jsonify({'error': request.args['error'], 'description': request.args.get('error_description')}), 400

    try:
        token = client.fetch_token(
            oauth_config.token_url,
            client_id=CLIENT_ID,
            include_client_id=True,  # public client
            code_verifier=code_verifier,
            authorization_response=request.url,
        )
    except Exception as e:
        # Surface OAuth2 exchange problems (e.g., PKCE verification failed, redirect mismatch)
        return jsonify({'error': 'token_exchange_failed', 'details': str(e)}), 400

    save_tokens(token)
    return redirect('/me')


def ensure_oauth_config():
    global oauth_config
    if oauth_config is None:
        assert FHIR_BASE_URL, 'FHIR_BASE_URL not set'
        oauth_config = smart_discover(FHIR_BASE_URL)


def get_authed_session() -> OAuth2Session:
    ensure_oauth_config()
    tok = load_tokens()
    assert tok, 'No tokens. Visit /login first.'
    extra = {
        'client_id': CLIENT_ID,
        'include_client_id': True,
    }
    sess = OAuth2Session(CLIENT_ID, token=tok, auto_refresh_url=oauth_config.token_url if oauth_config else None,
                         auto_refresh_kwargs=extra, token_updater=save_tokens)
    return sess


def get_userinfo(sess: OAuth2Session) -> Dict:
    ensure_oauth_config()
    # Prefer SMART well-known userinfo endpoint if available
    if oauth_config and oauth_config.userinfo_url:
        r = sess.get(oauth_config.userinfo_url)
        if r.ok:
            return r.json()
    # Fallback: common pattern replacing /authorize with /userinfo
    if oauth_config and oauth_config.authorize_url and '/authorize' in oauth_config.authorize_url:
        try:
            r = sess.get(oauth_config.authorize_url.replace('/authorize', '/userinfo'))
            if r.ok:
                return r.json()
        except Exception:
            pass
    # Fallback: parse id_token for fhirUser claim
    try:
        from jwt import decode as jwt_decode
        token = load_tokens() or {}
        idt = token.get('id_token')
        if idt:
            claims = jwt_decode(idt, options={"verify_signature": False, "verify_aud": False})
            return claims
    except Exception:
        pass
    return {}


def get_patient_id(sess: OAuth2Session) -> Optional[str]:
    info = get_userinfo(sess)
    fhir_user = info.get('fhirUser') if isinstance(info, dict) else None
    if fhir_user and isinstance(fhir_user, str) and fhir_user.startswith('Patient/'):
        return fhir_user.split('/', 1)[1]
    # Try a restricted Patient search
    pr = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient").json()
    if isinstance(pr, dict) and pr.get('entry'):
        try:
            return pr['entry'][0]['resource']['id']
        except Exception:
            return None
    return None

@app.route('/me')
def me():
    sess = get_authed_session()
    pid = get_patient_id(sess)
    out = { 'patient_id': pid }
    if pid:
        # Prefer instance-level $everything
        everything = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient/{pid}/$everything?_count=50")
        out['everything_status'] = everything.status_code
        try:
            out['everything_page'] = everything.json()
        except Exception:
            out['everything_page'] = {'note': 'Non-JSON response'}
        out['patient'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient/{pid}").json()
    else:
        # Fallback minimal patient bundle
        out['patient_bundle'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient").json()
    out['token'] = load_tokens()
    return jsonify(out)

@app.route('/sample')
def sample():
    sess = get_authed_session()
    patient_id = get_patient_id(sess)

    out = {}
    if patient_id:
        out['patient'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient/{patient_id}").json()
        out['observations'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Observation?patient={patient_id}&_count=20&_sort=-date").json()
        out['medication_statements'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/MedicationStatement?patient={patient_id}&_count=50").json()
        out['conditions'] = sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Condition?patient={patient_id}&_count=50").json()
    else:
        out['note'] = 'Could not determine patient id. Check scopes and userinfo.'

    return jsonify(out)

@app.route('/terms')
def terms():
    # Serve the local Terms & Conditions file
    return send_from_directory(os.getcwd(), 'terms.html')

@app.route('/debug')
def debug_info():
    info = {
        'client_id': CLIENT_ID,
        'fhir_base_url': FHIR_BASE_URL,
        'redirect_uri': REDIRECT_URI,
        'scopes': SCOPES.split() if SCOPES else [],
    }
    try:
        ensure_oauth_config()
        info['oauth'] = {
            'authorize_url': oauth_config.authorize_url if oauth_config else None,
            'token_url': oauth_config.token_url if oauth_config else None,
            'userinfo_url': oauth_config.userinfo_url if oauth_config else None,
        }
    except Exception as e:
        info['oauth_error'] = str(e)
    tok = load_tokens()
    info['has_tokens'] = bool(tok)
    if tok:
        info['token_keys'] = sorted([k for k in tok.keys() if not k.lower().endswith('token') or k == 'id_token'])
    return jsonify(info)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def write_export(filename: str, data: Dict) -> str:
    ensure_dir(EXPORT_DIR)
    out_path = os.path.join(EXPORT_DIR, filename)
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=2)
    return out_path


def fetch_everything_pages(sess: OAuth2Session, patient_id: str, max_pages: int = 10, count: int = 200):
    pages = []
    next_url = f"{FHIR_BASE_URL.rstrip('/')}/Patient/{patient_id}/$everything?_count={count}"
    total_entries = 0
    while next_url and len(pages) < max_pages:
        r = sess.get(next_url)
        if not r.ok:
            break
        bundle = r.json()
        pages.append(bundle)
        total_entries += len(bundle.get('entry', []))
        # find next link
        next_url = None
        for link in bundle.get('link', []) or []:
            if link.get('relation') == 'next':
                next_url = link.get('url')
                break
    return pages, total_entries

@app.route('/export')
def export_data():
    """Export patient data to a JSON file under exports/.
    Query params:
      - mode=sample (default) or mode=everything
    """
    sess = get_authed_session()
    pid = get_patient_id(sess)
    if not pid:
        return jsonify({'error': 'Could not determine patient id. Login and check scopes.'}), 400

    mode = (request.args.get('mode') or 'sample').lower()

    from datetime import datetime
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

    if mode == 'everything':
        pages, total = fetch_everything_pages(sess, pid)
        payload = {
            'patient_id': pid,
            'mode': 'everything',
            'page_count': len(pages),
            'total_entries_estimate': total,
            'everything_pages': pages,
        }
        fname = f"export_everything_patient_{pid}_{ts}.json"
        path = write_export(fname, payload)
        return jsonify({'status': 'ok', 'mode': 'everything', 'file': path, 'page_count': len(pages), 'entries': total})

    # default: sample
    sample = {
        'patient': sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Patient/{pid}").json(),
        'observations': sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Observation?patient={pid}&_count=50&_sort=-date").json(),
        'medication_statements': sess.get(f"{FHIR_BASE_URL.rstrip('/')}/MedicationStatement?patient={pid}&_count=200").json(),
        'conditions': sess.get(f"{FHIR_BASE_URL.rstrip('/')}/Condition?patient={pid}&_count=200").json(),
    }
    fname = f"export_sample_patient_{pid}_{ts}.json"
    path = write_export(fname, sample)
    return jsonify({'status': 'ok', 'mode': 'sample', 'file': path})

if __name__ == '__main__':
    # Optional HTTPS support for local redirect URIs that require https
    ssl_context = None
    https_env = os.getenv('HTTPS', '').lower()
    cert_file = os.getenv('CERT_FILE')
    key_file = os.getenv('KEY_FILE')
    if https_env in ('1', 'true', 'yes', 'adhoc'):
        if cert_file and key_file:
            ssl_context = (cert_file, key_file)
        else:
            # Use Werkzeug's self-signed certificate
            ssl_context = 'adhoc'
    # Disable debug/reloader to preserve PKCE code_verifier across /login -> /callback
    debug_flag = (os.getenv('FLASK_DEBUG', '') or os.getenv('DEBUG', '')).lower() in ('1', 'true', 'yes')
    app.run(host='127.0.0.1', port=PORT, debug=debug_flag, ssl_context=ssl_context, use_reloader=False)
