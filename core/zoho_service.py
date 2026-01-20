import requests
import json
from django.conf import settings

def get_zoho_access_token(token_env_var="ZOHO_MAIL_REFRESH_TOKEN"):
    """
    Gets a fresh Access Token using a specific Refresh Token from settings.
    Ported from Next.js logic.
    """
    print(f"[Auth] Requesting Access Token using var: {token_env_var}")

    # FIX: Explicitly select the variable based on the argument
    refresh_token = None
    if token_env_var == "ZOHO_MAIL_REFRESH_TOKEN":
        refresh_token = settings.ZOHO_MAIL_REFRESH_TOKEN
    else:
        # Fallback or other tokens if needed
        refresh_token = getattr(settings, "ZOHO_REFRESH_TOKEN", None)

    # Debug: Check if token exists
    if not refresh_token:
        print(f"[Auth] ❌ MISSING REFRESH TOKEN in settings: {token_env_var}")
        return None
    else:
        # Show first 4 chars for debug safety
        print(f"[Auth] Found Refresh Token (starts with: {refresh_token[:4]}...)")

    client_id = settings.ZOHO_CLIENT_ID
    client_secret = settings.ZOHO_CLIENT_SECRET
    accounts_domain = settings.ZOHO_ACCOUNTS_DOMAIN or "https://accounts.zoho.in"

    if not client_id or not client_secret:
        print("[Auth] Zoho ClientID or Secret missing.")
        return None

    # Construct the URL
    refresh_url = f"{accounts_domain}/oauth/v2/token"
    params = {
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'refresh_token'
    }

    try:
        # In Python requests, we pass params as a dictionary for automatic encoding
        response = requests.post(refresh_url, params=params)
        
        # Check for non-200 status *before* parsing JSON to catch generic 404/500s
        if response.status_code != 200:
            print(f"[Auth] ❌ Zoho HTTP Error: {response.status_code}")
            print(f"Response: {response.text}")
            return None

        data = response.json()

        if 'error' in data:
            print(f"[Auth] ❌ Zoho Token API Error ({token_env_var}): {json.dumps(data)}")
            return None
        
        print(f"[Auth] ✅ Successfully retrieved Access Token for {token_env_var}")
        return data.get('access_token')

    except Exception as e:
        print(f"[Auth] Error refreshing Zoho token for {token_env_var}: {str(e)}")
        return None

def send_zoho_email(to_email, subject, html_content):
    """
    Sends an email to the user via Zoho Mail API.
    Uses the ZOHO_MAIL_REFRESH_TOKEN to get a fresh access token first.
    """
    account_id = settings.ZOHO_MAIL_ACCOUNT_ID
    from_address = settings.ZOHO_MAIL_FROM
    
    # Dynamic Mail Domain to match your account region (Default: mail.zoho.in)
    mail_api_domain = settings.ZOHO_MAIL_API_DOMAIN or "mail.zoho.in"

    if not account_id or not from_address:
        print("Missing ZOHO_MAIL_ACCOUNT_ID or ZOHO_MAIL_FROM. Skipping email.")
        return False, "Missing Configuration"

    print(f"[Email] Attempting to send email to {to_email} via {mail_api_domain}...")

    try:
        # Explicitly use the Mail token logic
        access_token = get_zoho_access_token("ZOHO_MAIL_REFRESH_TOKEN")
        
        if not access_token:
            print("[Email] ❌ Could not get Access Token. Aborting email.")
            return False, "Could not get Access Token"

        email_payload = {
            "fromAddress": from_address,
            "toAddress": to_email,
            "subject": subject,
            "content": html_content,
            "askReceipt": "yes" # Optional: requests a read receipt
        }

        mail_api_url = f"https://{mail_api_domain}/api/accounts/{account_id}/messages"
        
        headers = {
            'Authorization': f'Zoho-oauthtoken {access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(mail_api_url, headers=headers, json=email_payload)

        if response.status_code not in [200, 201]:
            print(f"[Email] ❌ Failed to send: {response.status_code} - {response.text}")
            return False, f"Zoho API Error: {response.text}"
        else:
            print("[Email] ✅ Email sent successfully.")
            return True, "Email sent successfully"

    except Exception as e:
        print(f"[Email] Error sending email: {str(e)}")
        return False, str(e)