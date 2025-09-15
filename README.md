# ReadEpicData (UCSF MyHealth, FHIR R4, SMART on FHIR user access)

This small Python app lets a UCSF patient use SMART on FHIR (R4) with OAuth2 + PKCE to log in with UCSF MyChart (MyHealth) and download their data (e.g., Patient, Observations, Medications, Conditions).

What you need
- A UCSF MyChart (MyHealth) account.
- A registered “Standalone Patient” app on Epic’s FHIR developer site so you get a public Client ID. Choose a redirect URI of: http://127.0.0.1:8765/callback
  - App type: Patient/consumer app (public client, no client secret). Enable offline_access.
- UCSF FHIR R4 base URL. The app will auto-discover auth endpoints from the FHIR server’s SMART configuration.

Find UCSF FHIR endpoints
- Visit Epic’s FHIR Endpoints directory, search “UCSF Health,” choose the R4 endpoint. Copy the FHIR base URL.
- You can also use the CapabilityStatement/.well-known to auto-discover OAuth endpoints; this app does that automatically from your base URL.

Setup
1) Copy env template and fill in values
   cp .env.example .env
   - CLIENT_ID: your Epic app’s client ID
   - FHIR_BASE_URL: UCSF’s R4 FHIR base URL
   - REDIRECT_URI: http://127.0.0.1:8765/callback (must match what you registered)
   - SCOPES (default is fine): openid fhirUser launch/patient patient/*.read offline_access

2) Create venv and install
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

Run
- With the venv active:
  python app.py
- Your browser will open to UCSF MyChart login. Sign in and approve access.
- The app will fetch and print:
  - Your Patient resource
  - Recent Observations (last 20)
  - Your Medications and Conditions (sample calls)
- Tokens are saved to tokens.json for refresh.

Notes
- This is a public client using PKCE; no client secret is used or stored.
- Scopes: patient/*.read is broad read-only access. Add more specific scopes if needed.
- For other Epic orgs, only change FHIR_BASE_URL.

Troubleshooting
- If discovery fails, confirm FHIR_BASE_URL is the R4 base and is reachable.
- Ensure the redirect URI in .env exactly matches what you registered in your Epic app settings.
- If UCSF requires whitelisting the app in a patient portal “Connected Apps” section, enable it in MyChart first.
