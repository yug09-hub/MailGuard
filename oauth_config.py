"""
OAuth2 Configuration for Email Providers
=========================================
Supports Google OAuth2 for Gmail IMAP access.
"""

import os

# OAuth2 Configuration
# To set up, go to https://console.cloud.google.com/
# Create a project, enable Gmail API, and create OAuth2 credentials

OAUTH_CONFIG = {
    'google': {
        'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
        'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'refresh_url': 'https://oauth2.googleapis.com/token',
        'scope': [
            'https://mail.google.com/',  # Full Gmail access
            'https://www.googleapis.com/auth/userinfo.email',
            'openid',
        ],
        'imap_server': 'imap.gmail.com',
        'imap_port': 993,
    }
}

# For demo/development - you can set these directly (not recommended for production)
# Or use environment variables
DEFAULT_REDIRECT_URI = 'http://127.0.0.1:5000/oauth/callback'


def get_oauth_url(provider='google', redirect_uri=None):
    """Generate OAuth2 authorization URL."""
    config = OAUTH_CONFIG.get(provider)
    if not config:
        return None
    
    redirect_uri = redirect_uri or DEFAULT_REDIRECT_URI
    
    params = {
        'client_id': config['client_id'],
        'redirect_uri': redirect_uri,
        'scope': ' '.join(config['scope']),
        'response_type': 'code',
        'access_type': 'offline',  # Get refresh token
        'prompt': 'consent',  # Force consent screen to get refresh token
    }
    
    from urllib.parse import urlencode
    return f"{config['authorize_url']}?{urlencode(params)}"


def exchange_code_for_token(provider, code, redirect_uri=None):
    """Exchange authorization code for access token."""
    import requests
    
    config = OAUTH_CONFIG.get(provider)
    if not config:
        return None
    
    redirect_uri = redirect_uri or DEFAULT_REDIRECT_URI
    
    data = {
        'code': code,
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    
    response = requests.post(config['token_url'], data=data)
    if response.status_code == 200:
        return response.json()
    return None


def refresh_access_token(provider, refresh_token):
    """Refresh expired access token."""
    import requests
    
    config = OAUTH_CONFIG.get(provider)
    if not config:
        return None
    
    data = {
        'refresh_token': refresh_token,
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'grant_type': 'refresh_token',
    }
    
    response = requests.post(config['refresh_url'], data=data)
    if response.status_code == 200:
        return response.json()
    return None
