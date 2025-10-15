import resend
import os
from dotenv import load_dotenv
import requests
import logging

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

async def send_verification_email(email: str, token: str):
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    link = f"{frontend_url}/verify-email?token={token}"
    try:
        logging.info(f"Sending verification email to {email}...")
        resend.Emails.send({
            "from": "Kick-Start Digital Hub <onboarding@resend.dev>",
            "to": email,
            "subject": "Verify your Kick-start account",
            "html": f"""
                <h2>Welcome to Kick-Start Digital Hub 🎉</h2>
                <p>Click the link below to verify your email address:</p>
                <a href="{link}" target="_blank">{link}</a>
            """
        })
       
        logging.info("✅ Email sent successfully via Resend.")
    
    except Exception as e: 
        logging.error(f"❌ Failed to send email via Resend: {e}")
        raise

async def send_password_reset_email(email: str, token: str):
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    reset_link = f"{frontend_url}/reset?token={token}"
    
    logging.info(f"Sending password reset email to {email}...")

    resend.Emails.send({  # <- don't await this!
        "from": "Kick-Start Digital Hub<onboarding@resend.dev>",
        "to": email,
        "subject": "Reset Password",
        "html": f"""
            <h2>Password Reset Request</h2>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_link}" target="_blank">{reset_link}</a>
        """
    })

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "oluwadamilolaayodele21@gmail.com")

def send_admin_contact_notification(name: str, email: str, subject: str, message: str):
    if not RESEND_API_KEY:
        raise ValueError("Missing RESEND_API_KEY")

    payload = {
        "from": "Kick-Start Digital Hub <onboarding@resend.dev>",
        "to": [ADMIN_EMAIL],
        "subject": f"New Contact Message: {subject}",
        "html": f"""
            <p><strong>You received a new contact message from Kick-Start Digital HubMediVult:</strong></p>
            <ul>
                <li><strong>Name:</strong> {name}</li>
                <li><strong>Email:</strong> {email}</li>
                <li><strong>Subject:</strong> {subject}</li>
            </ul>
            <p><strong>Message:</strong></p>
            <p>{message}</p>
        """
    }

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post("https://api.resend.com/emails", json=payload, headers=headers)

    if response.status_code >= 400:
        raise Exception(f"Failed to send contact message to admin: {response.text}")
