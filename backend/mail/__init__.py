"""Email delivery for the six-digit codes (registration and login).

  messages.py   who may receive which code, and the two message templates
  delivery.py   SmtpMailer (real email, always over TLS), DevOutboxMailer (development
                only: messages written to .eml files; refused in production),
                create_mailer(settings) and send_otp_email(...)

Rules kept here:
  * a code is only ever put into the email itself: never logged, never returned, never
    stored (the database keeps only its HMAC, see backend/auth/otp.py);
  * logs name the purpose and a masked recipient (u***@example.com), nothing else;
  * errors use fixed messages: never the SMTP password, the code, the server's reply or
    the original exception;
  * a code is sent only to the address of an account that may receive it: registration
    codes to accounts awaiting email verification, login codes to active accounts.
"""
