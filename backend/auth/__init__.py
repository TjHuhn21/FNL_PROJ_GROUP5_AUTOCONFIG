"""Authentication security building blocks (Phase 1): pure functions, no I/O.

  policy     the approved authentication policy (validated; can only be made stricter)
  passwords  Argon2id password hashing, verification, parameter checks, rehash detection
  otp        six-digit email codes and their peppered HMAC-SHA256 (registration and login)
  tokens     256-bit session tokens and their SHA-256 hash

Nothing here connects to a database, sends email, reads files or logs a secret. Values
that must stay secret (a code, a token) are hidden from repr(), and no error message
ever repeats a password, code, token or pepper. These modules are separate from the
desktop's device-password encryption (security.py, FERNET_KEY), which they never use.
"""
