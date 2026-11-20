"""Desktop side of NetCommand sign-in: talks to the backend's /auth and /admin API.

  api_client.py   AuthApiClient: the HTTP calls (standard library only)
  session.py      AuthSession (the session token, in memory only) and Access (what each
                  role may do in the GUI)

Nothing here hashes passwords, checks codes or decides who may sign in: the backend
does. NetCommand user accounts are unrelated to the device logins that security.py
encrypts; nothing here touches those.
"""
