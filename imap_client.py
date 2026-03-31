"""
IMAP Email Client for MailGuard
================================
Secure email fetching using IMAP with automatic spam classification.
No passwords are stored - only session tokens.
"""

import imaplib
import email
import re
import uuid
import ssl
from datetime import datetime
from email.header import decode_header
from email.utils import parsedate_to_datetime


def get_oauth2_string(user, access_token):
    """Generate OAuth2 authentication string for IMAP."""
    auth_string = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
    return auth_string


# Common IMAP server configurations
IMAP_SERVERS = {
    'gmail.com': {'server': 'imap.gmail.com', 'port': 993, 'ssl': True},
    'outlook.com': {'server': 'outlook.office365.com', 'port': 993, 'ssl': True},
    'hotmail.com': {'server': 'outlook.office365.com', 'port': 993, 'ssl': True},
    'live.com': {'server': 'outlook.office365.com', 'port': 993, 'ssl': True},
    'yahoo.com': {'server': 'imap.mail.yahoo.com', 'port': 993, 'ssl': True},
    'icloud.com': {'server': 'imap.mail.me.com', 'port': 993, 'ssl': True},
    'me.com': {'server': 'imap.mail.me.com', 'port': 993, 'ssl': True},
}


def detect_imap_server(email_address):
    """Auto-detect IMAP server based on email domain."""
    domain = email_address.split('@')[-1].lower()
    
    # Check exact domain match
    if domain in IMAP_SERVERS:
        return IMAP_SERVERS[domain]
    
    # Check for Gmail workspace/custom domains
    if 'gmail' in domain or 'google' in domain:
        return IMAP_SERVERS['gmail.com']
    
    # Check for Microsoft/Outlook
    if 'outlook' in domain or 'microsoft' in domain or 'office365' in domain:
        return IMAP_SERVERS['outlook.com']
    
    # Default to standard IMAP settings
    return {'server': f'imap.{domain}', 'port': 993, 'ssl': True}


def decode_mime_words(s):
    """Decode MIME encoded words in email headers."""
    if not s:
        return ""
    
    decoded_words = decode_header(s)
    result = []
    
    for word, charset in decoded_words:
        if isinstance(word, bytes):
            try:
                result.append(word.decode(charset or 'utf-8', errors='replace'))
            except:
                result.append(word.decode('utf-8', errors='replace'))
        else:
            result.append(word)
    
    return ''.join(result)


def clean_text(text):
    """Clean and normalize email text."""
    if not text:
        return ""
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove common email artifacts
    text = re.sub(r'>+\s*', '', text)
    
    return text.strip()


def extract_email_body(msg):
    """Extract the main body text from an email message."""
    body = ""
    
    if msg.is_multipart():
        # Try to get text/plain part first
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
            
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
                    break
                except:
                    continue
        
        # If no plain text, try HTML
        if not body:
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                if "attachment" in content_disposition:
                    continue
                
                if content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html = payload.decode(charset, errors='replace')
                        # Simple HTML to text conversion
                        body = re.sub(r'<[^>]+>', ' ', html)
                        body = clean_text(body)
                        break
                    except:
                        continue
    else:
        # Single part message
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='replace')
        except:
            body = str(msg.get_payload())
    
    return clean_text(body)


def parse_email(msg, uid):
    """Parse an email message into a dictionary."""
    # Extract headers
    subject = decode_mime_words(msg.get('Subject', '(No Subject)'))
    sender = decode_mime_words(msg.get('From', 'Unknown'))
    recipient = decode_mime_words(msg.get('To', ''))
    date_str = msg.get('Date', '')
    
    # Parse date
    try:
        date = parsedate_to_datetime(date_str)
        date_iso = date.isoformat()
    except:
        date_iso = datetime.now().isoformat()
    
    # Extract body
    body = extract_email_body(msg)
    
    return {
        'uid': str(uid),
        'subject': subject,
        'sender': sender,
        'recipient': recipient,
        'date': date_iso,
        'body': body,
        'raw_size': len(body),
    }


class IMAPClient:
    """Secure IMAP client for fetching emails."""
    
    def __init__(self, email_address, app_password=None, imap_server=None, port=993, 
                 use_oauth2=False, access_token=None):
        self.email_address = email_address
        self.app_password = app_password
        self.access_token = access_token
        self.use_oauth2 = use_oauth2
        self.connection = None
        self.session_id = str(uuid.uuid4())
        
        # Auto-detect server if not provided
        if not imap_server:
            config = detect_imap_server(email_address)
            self.imap_server = config['server']
            self.port = config['port']
            self.use_ssl = config['ssl']
        else:
            self.imap_server = imap_server
            self.port = port
            self.use_ssl = True
    
    def connect(self):
        """Connect to IMAP server and login."""
        try:
            # Create a more robust SSL context
            ssl_context = ssl.create_default_context()
            
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.imap_server, self.port, ssl_context=ssl_context)
            else:
                self.connection = imaplib.IMAP4(self.imap_server, self.port)
            
            # Login with OAuth2 or regular password
            if self.use_oauth2 and self.access_token:
                # OAuth2 authentication
                auth_string = get_oauth2_string(self.email_address, self.access_token)
                self.connection.authenticate('XOAUTH2', lambda x: auth_string.encode())
            else:
                # Regular password authentication
                self.connection.login(self.email_address, self.app_password)
            return True
        except imaplib.IMAP4.error as e:
            # Handle specific IMAP errors for better reporting
            raise Exception(f"IMAP authentication failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Connection to {self.imap_server} failed: {str(e)}")
    
    def disconnect(self):
        """Disconnect from IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except:
                pass
            self.connection = None
    
    def fetch_latest_emails(self, folder='INBOX', limit=20):
        """Fetch latest emails from specified folder."""
        if not self.connection:
            raise Exception("Not connected to IMAP server")
        
        try:
            # Select folder
            status, _ = self.connection.select(folder, readonly=True)
            if status != 'OK':
                raise Exception(f"Could not select folder: {folder}")
            
            # Search for all emails
            status, messages = self.connection.search(None, 'ALL')
            if status != 'OK':
                raise Exception("Could not search emails")
            
            # Get message IDs
            message_ids = messages[0].split()
            
            # Get the latest 'limit' emails
            latest_ids = message_ids[-limit:] if len(message_ids) > limit else message_ids
            latest_ids.reverse()  # Most recent first
            
            emails = []
            for msg_id in latest_ids:
                try:
                    # Fetch email
                    status, msg_data = self.connection.fetch(msg_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    email_data = parse_email(msg, msg_id.decode())
                    emails.append(email_data)
                except Exception as e:
                    print(f"Error parsing email {msg_id}: {e}")
                    continue
            
            return emails
            
        except Exception as e:
            raise Exception(f"Failed to fetch emails: {str(e)}")
    
    def test_connection(self):
        """Test IMAP connection without fetching emails."""
        try:
            self.connect()
            # List folders to verify access
            status, _ = self.connection.list()
            self.disconnect()
            return status == 'OK'
        except Exception as e:
            return False
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


# Global session storage (in-memory for active connections)
# In production, consider using Redis or similar
active_sessions = {}


def create_session(email_address, app_password, imap_server=None):
    """Create a new IMAP session and return session ID."""
    client = IMAPClient(email_address, app_password, imap_server)
    
    # Connect directly - this will raise a descriptive Exception if it fails
    client.connect()
    
    # List folders to verify we have full access (some logins succeed but lack permissions)
    try:
        status, _ = client.connection.list()
        if status != 'OK':
            client.disconnect()
            raise Exception("Authenticated successfully, but could not list mailbox folders.")
    except Exception as e:
        client.disconnect()
        raise Exception(f"Failed to verify mailbox access: {str(e)}")
    
    # Store session
    active_sessions[client.session_id] = {
        'client': client,
        'email_address': email_address,
        'imap_server': client.imap_server,
        'created_at': datetime.now().isoformat(),
    }
    
    return client.session_id


def get_session(session_id):
    """Get an active IMAP session."""
    return active_sessions.get(session_id)


def close_session(session_id):
    """Close and remove an IMAP session."""
    session = active_sessions.pop(session_id, None)
    if session:
        try:
            session['client'].disconnect()
        except:
            pass
    return session is not None


def fetch_with_session(session_id, limit=20):
    """Fetch emails using an existing session."""
    session = get_session(session_id)
    if not session:
        raise Exception("Session not found or expired")
    
    client = session['client']
    
    # Connect if not already connected
    if not client.connection:
        client.connect()
    
    # Fetch emails
    emails = client.fetch_latest_emails(limit=limit)
    
    return emails
