from __future__ import print_function
import os.path
import base64
import email
from email.header import decode_header
import datetime

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Define the scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def main():
    """Read emails from Gmail and print details."""
    creds = None
    # Check for existing credentials
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # Authenticate if credentials are invalid or don't exist
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for future runs
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Build the Gmail service
    service = build('gmail', 'v1', credentials=creds)

    # Fetch emails from the inbox
    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    if not messages:
        print('No messages found.')
        return

    # Iterate through each email
    for message in messages[:5]:
        msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
        headers = msg['payload']['headers']

        # Initialize variables
        subject = ''
        sender = ''
        to = ''
        cc = ''
        date = ''

        # Extract email headers
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
            elif header['name'] == 'To':
                to = header['value']
            elif header['name'] == 'Cc':
                cc = header['value']
            elif header['name'] == 'Date':
                date = header['value']

        # Decode the subject if it's encoded
        decoded_subject = decode_header(subject)[0][0]
        if isinstance(decoded_subject, bytes):
            decoded_subject = decoded_subject.decode()
        subject = decoded_subject

        # Print email details
        print(f"From: {sender}")
        print(f"To: {to}")
        if cc:
            print(f"Cc: {cc}")
        print(f"Date: {date}")
        print(f"Subject: {subject}")

        # Extract the email body
        parts = msg['payload'].get('parts', [])
        body = ''
        if parts:
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    text = base64.urlsafe_b64decode(data).decode('utf-8')
                    body += text
        else:
            # Handle emails without multiple parts
            data = msg['payload']['body']['data']
            body = base64.urlsafe_b64decode(data).decode('utf-8')

        print("Body:")
        print(body)
        print("=" * 50)

if __name__ == '__main__':
    main()
