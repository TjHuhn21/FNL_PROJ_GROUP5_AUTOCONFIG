"""Partly hidden email addresses for screens and logs (no I/O, no other imports).

mask_email('jfontillaz.9008@umak.edu.ph') -> 'jf*****08@umak.edu.ph'
The backend's copy (audit details). The desktop has the same function in
gui/auth_window.py (its sign-in code never imports the backend, and the backend never
imports the desktop); tests/test_auth_ui.py checks that both give the same result.
"""
MASK = '*****'              # always 5, so the masked text does not reveal the name's length
NO_EMAIL_TEXT = 'your email'


def mask_email(email):
    """The name before the @ is partly hidden (first 2 + ***** + last 2; names of 4
    characters or fewer: first 1 + *****), the domain is kept. Display only.
    Empty or no '@' -> 'your email'."""
    local, at, domain = (email or '').strip().rpartition('@')
    if not at or not local or not domain:
        return NO_EMAIL_TEXT
    if len(local) <= 4:
        return f'{local[0]}{MASK}@{domain}'
    return f'{local[:2]}{MASK}{local[-2:]}@{domain}'
