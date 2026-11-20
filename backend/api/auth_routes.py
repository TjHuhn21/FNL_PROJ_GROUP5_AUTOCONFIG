"""Authentication and account-administration endpoints: a thin HTTP layer over AuthService.

  POST /auth/register            202  a registration code is emailed (same answer for any address)
  POST /auth/register/verify     200  {"status": "pending_approval"}
  POST /auth/register/resend     202  same answer for any address
  POST /auth/login               202  password correct: a login code is emailed (NO session yet)
  POST /auth/login/verify        200  the session token, once
  POST /auth/login/resend        202  needs the open login challenge
  POST /auth/logout              204  (Authorization: Bearer <token>)
  GET  /auth/session             200  who is signed in
  GET  /admin/users              200  accounts (admin)
  POST /admin/users/{id}/approve 200  (admin)
  POST /admin/users/{id}/reject  200  (admin)
  POST /admin/users/{id}/disable 200  (admin; ends the account's sessions)
  POST /admin/users/{id}/role    200  (admin; {"role": ...}; ends the account's sessions)

Rules kept here (everything else is AuthService's job):
  * tokens only in the Authorization: Bearer header; never in URLs or responses other
    than POST /auth/login/verify; responses are marked Cache-Control: no-store;
  * request bodies: JSON, unknown fields refused, every string length-capped, at most
    MAX_BODY_BYTES per request;
  * errors are fixed messages with a short code: no account detail, no internal error;
  * the service is built on first use (no database connection when the app is created,
    imported or its documentation opened). Database, mail or configuration problems
    become 503 "temporarily unavailable"; their cause is logged as a class name only;
  * per-IP request limit for these routes, on top of the service's own limits (which also
    cover unknown email addresses). Both are kept in this process's memory: the backend
    must run as ONE process (python -m backend does) for the limits to hold.

Nothing from backend.database, the service or the mail layer is imported at module level:
GET /health must never load them.
"""
import logging
import threading
from typing import Literal, Optional

from fastapi import APIRouter, Body, Depends, FastAPI, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from backend.auth.errors import (AccountNotActive, AuthError, CodeInvalid, DeliveryFailed,
                                 InvalidRequest, LoginFailed, NotAuthenticated, NotPermitted,
                                 RetryLater, ServiceUnavailable)
from backend.auth.rate_limit import Limit, SlidingWindowLimiter

log = logging.getLogger('backend.api')

MAX_BODY_BYTES = 8 * 1024
MAX_TOKEN_LENGTH = 128
API_LIMIT_PER_IP = Limit(120, 60)              # all /auth and /admin requests, per client IP
WORKSTATION_HEADER = 'X-NetCommand-Workstation'
PROTECTED_PREFIXES = ('/auth/', '/admin/')
ROLES = ('admin', 'operator', 'viewer')
STATUSES = ('pending_verification', 'pending_approval', 'active', 'rejected', 'disabled')

# error class -> (HTTP status, short code for clients)
ERRORS = (
    (InvalidRequest, 400, 'invalid_request'),
    (CodeInvalid, 400, 'code_invalid'),
    (LoginFailed, 401, 'login_failed'),
    (NotAuthenticated, 401, 'not_authenticated'),
    (AccountNotActive, 403, 'account_not_active'),
    (NotPermitted, 403, 'not_permitted'),
    (RetryLater, 429, 'rate_limited'),
    (DeliveryFailed, 503, 'delivery_failed'),
    (ServiceUnavailable, 503, 'unavailable'),
)


# ---------------------------------------------------------------- request bodies
class _Body(BaseModel):
    model_config = ConfigDict(extra='forbid')


ChallengeId = Field(min_length=20, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')


class RegisterBody(_Body):
    email: str = Field(min_length=3, max_length=254)
    full_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=512)


class EmailBody(_Body):
    email: str = Field(min_length=3, max_length=254)


class LoginBody(_Body):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=512)


class VerifyBody(_Body):
    challenge_id: str = ChallengeId
    code: str = Field(min_length=1, max_length=32)


class ChallengeBody(_Body):
    challenge_id: str = ChallengeId


class ApproveBody(_Body):
    role: Optional[Literal['admin', 'operator', 'viewer']] = None


class RoleBody(_Body):
    role: Literal['admin', 'operator', 'viewer']


# ---------------------------------------------------------------- the service
_build_lock = threading.Lock()


def get_auth_service(request: Request):
    """The app's AuthService, built on first use from the app's settings."""
    state = request.app.state
    service = getattr(state, 'auth_service', None)
    if service is not None:
        return service
    with _build_lock:
        if getattr(state, 'auth_service', None) is None:
            settings = state.settings
            if settings.database is None:
                log.warning('Authentication unavailable: the database is not configured')
                raise ServiceUnavailable()
            state.auth_service = guarded(_build_service, settings)
        return state.auth_service


def _build_service(settings):
    from backend.auth.service import AuthService
    return AuthService.from_settings(settings)


def guarded(fn, *args, **kwargs):
    """Run a service call; database, mail and configuration failures become
    ServiceUnavailable (logged by class name only), a stray InvalidValue InvalidRequest."""
    try:
        return fn(*args, **kwargs)
    except AuthError:
        raise
    except Exception as err:
        from backend.auth.otp import OtpConfigurationError
        from backend.database.errors import InvalidValue, RepositoryError
        from backend.mail.delivery import MailError
        if isinstance(err, InvalidValue):
            raise InvalidRequest(str(err)) from None
        if isinstance(err, (RepositoryError, MailError, OtpConfigurationError)):
            log.warning('Authentication unavailable: %s', type(err).__name__)
            raise ServiceUnavailable() from None
        raise


def client_context(request: Request):
    label = request.headers.get(WORKSTATION_HEADER)
    return {'client_ip': request.client.host if request.client else None,
            'workstation_label': label}


def api_rate_limit(request: Request):
    limiter = request.app.state.api_limiter
    ip = request.client.host if request.client else 'unknown'
    wait = limiter.hit(('api', ip), API_LIMIT_PER_IP)
    if wait:
        raise RetryLater(wait)


# ---------------------------------------------------------------- reusable security dependencies
_bearer = HTTPBearer(auto_error=False, description='The session token from POST /auth/login/verify')


def bearer_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)):
    """The raw token from 'Authorization: Bearer <token>'; NotAuthenticated if the header is
    missing, uses another scheme or is malformed. Never taken from the URL."""
    if credentials is None:
        raise NotAuthenticated()
    token = credentials.credentials.strip()
    if not token or len(token) > MAX_TOKEN_LENGTH or ' ' in token:
        raise NotAuthenticated()
    return token


def current_session(token: str = Depends(bearer_token), service=Depends(get_auth_service)):
    """The signed-in session (SessionInfo). Revoked, expired, idle and disabled-account
    sessions are refused (401)."""
    return guarded(service.validate_session, token)


def require_roles(*roles):
    """Dependency factory: the session, if its role is one of `roles` (403 otherwise,
    audited)."""
    for role in roles:
        if role not in ROLES:
            raise ValueError(f'Unknown role: {role}')

    def dependency(request: Request, token: str = Depends(bearer_token),
                   service=Depends(get_auth_service)):
        return guarded(service.authorize, token, roles,
                       action='auth.authorize', **client_context(request))
    return dependency


require_admin = require_roles('admin')
require_operator = require_roles('operator', 'admin')     # scan, configure, apply (later)
require_viewer = require_roles('viewer', 'operator', 'admin')


# ---------------------------------------------------------------- responses
def _error_response(err):
    for cls, status, code in ERRORS:
        if isinstance(err, cls):
            break
    else:
        status, code = 400, 'invalid_request'
    headers = {'Cache-Control': 'no-store'}
    if isinstance(err, RetryLater):
        headers['Retry-After'] = str(err.retry_after_seconds)
    if status == 401:
        headers['WWW-Authenticate'] = 'Bearer'
    return JSONResponse(status_code=status, content={'detail': str(err), 'error': code},
                        headers=headers)


def _code_sent(sent, message):
    return JSONResponse(status_code=202, headers={'Cache-Control': 'no-store'},
                        content={'challenge_id': sent.challenge_id,
                                 'expires_in_seconds': sent.expires_in_seconds,
                                 'message': message})


def _no_change(message):
    return JSONResponse(status_code=409, headers={'Cache-Control': 'no-store'},
                        content={'detail': message, 'error': 'no_change'})


REGISTER_MESSAGE = ('If this email address can be registered, a verification code has been '
                    'sent to it.')
LOGIN_MESSAGE = 'A sign-in code has been sent to your email address.'


# ---------------------------------------------------------------- routes
auth = APIRouter(prefix='/auth', tags=['authentication'], dependencies=[Depends(api_rate_limit)])
admin = APIRouter(prefix='/admin', tags=['administration'],
                  dependencies=[Depends(api_rate_limit)])


@auth.post('/register', status_code=202)
def register(request: Request, body: RegisterBody, service=Depends(get_auth_service)):
    sent = guarded(service.register, body.email, body.full_name, body.password,
                   **client_context(request))
    return _code_sent(sent, REGISTER_MESSAGE)


@auth.post('/register/verify')
def verify_registration(request: Request, body: VerifyBody, service=Depends(get_auth_service)):
    status = guarded(service.verify_registration, body.challenge_id, body.code,
                     **client_context(request))
    return JSONResponse({'status': status}, headers={'Cache-Control': 'no-store'})


@auth.post('/register/resend', status_code=202)
def resend_registration(request: Request, body: EmailBody, service=Depends(get_auth_service)):
    sent = guarded(service.resend_registration_code, body.email, **client_context(request))
    return _code_sent(sent, REGISTER_MESSAGE)


@auth.post('/login', status_code=202)
def login(request: Request, body: LoginBody, service=Depends(get_auth_service)):
    sent = guarded(service.login, body.email, body.password, **client_context(request))
    return _code_sent(sent, LOGIN_MESSAGE)


@auth.post('/login/verify')
def verify_login(request: Request, body: VerifyBody, service=Depends(get_auth_service)):
    result = guarded(service.verify_login, body.challenge_id, body.code,
                     **client_context(request))
    return JSONResponse(
        {'token': result.token, 'token_type': 'bearer', 'user_id': result.user_id,
         'role': result.role, 'session_id': result.session_id,
         'expires_in_seconds': result.expires_in_seconds,
         'idle_timeout_seconds': result.idle_timeout_seconds},
        headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})


@auth.post('/login/resend', status_code=202)
def resend_login(request: Request, body: ChallengeBody, service=Depends(get_auth_service)):
    sent = guarded(service.resend_login_code, body.challenge_id, **client_context(request))
    return _code_sent(sent, LOGIN_MESSAGE)


@auth.post('/logout', status_code=204)
def logout(request: Request, token: str = Depends(bearer_token),
           service=Depends(get_auth_service)):
    """Ends this session. Always 204 for a well-formed header (an unknown or already
    ended session has nothing left to end)."""
    guarded(service.logout, token, **client_context(request))
    return Response(status_code=204, headers={'Cache-Control': 'no-store'})


@auth.get('/session')
def session(info=Depends(current_session)):
    return JSONResponse({'user_id': info.user_id, 'role': info.role,
                         'session_id': info.session_id},
                        headers={'Cache-Control': 'no-store'})


@admin.get('/users')
def list_users(status: Optional[Literal[STATUSES]] = Query(None),
               limit: int = Query(100, ge=1, le=1000),
               after_id: Optional[int] = Query(None, ge=1, le=2 ** 63 - 1),
               token: str = Depends(bearer_token), _admin=Depends(require_admin),
               service=Depends(get_auth_service)):
    rows = guarded(service.list_accounts, token, status=status, limit=limit, after_id=after_id)
    from fastapi.encoders import jsonable_encoder
    return JSONResponse({'users': jsonable_encoder(rows)}, headers={'Cache-Control': 'no-store'})


UserId = Path(ge=1, le=2 ** 63 - 1)


@admin.post('/users/{user_id}/approve')
def approve_user(request: Request, user_id: int = UserId,
                 body: Optional[ApproveBody] = Body(None), token: str = Depends(bearer_token),
                 _admin=Depends(require_admin), service=Depends(get_auth_service)):
    role = body.role if body else None
    if not guarded(service.approve_account, token, user_id, role, **client_context(request)):
        return _no_change('The account is not waiting for approval.')
    return JSONResponse({'user_id': user_id, 'status': 'active'},
                        headers={'Cache-Control': 'no-store'})


@admin.post('/users/{user_id}/reject')
def reject_user(request: Request, user_id: int = UserId, token: str = Depends(bearer_token),
                _admin=Depends(require_admin), service=Depends(get_auth_service)):
    if not guarded(service.reject_account, token, user_id, **client_context(request)):
        return _no_change('The account is not waiting for approval.')
    return JSONResponse({'user_id': user_id, 'status': 'rejected'},
                        headers={'Cache-Control': 'no-store'})


@admin.post('/users/{user_id}/role')
def change_role(request: Request, body: RoleBody, user_id: int = UserId,
                token: str = Depends(bearer_token), _admin=Depends(require_admin),
                service=Depends(get_auth_service)):
    """Change another account's role (admin only). The account is signed out everywhere
    and signs in again with the new role. 409 if it already has that role; 400 for one's
    own account or when it would leave no active admin."""
    result = guarded(service.change_role, token, user_id, body.role, **client_context(request))
    if result is None:
        return _no_change('The account already has this role.')
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})


@admin.post('/users/{user_id}/disable')
def disable_user(request: Request, user_id: int = UserId, token: str = Depends(bearer_token),
                 _admin=Depends(require_admin), service=Depends(get_auth_service)):
    if not guarded(service.disable_account, token, user_id, **client_context(request)):
        return _no_change('The account does not exist or is already disabled.')
    return JSONResponse({'user_id': user_id, 'status': 'disabled'},
                        headers={'Cache-Control': 'no-store'})


# ---------------------------------------------------------------- body size limit
class BodySizeLimit:
    """ASGI middleware: requests to the authentication routes may carry at most
    max_bytes of body (checked on Content-Length AND on the bytes actually received)."""

    def __init__(self, app, max_bytes=MAX_BODY_BYTES):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope['path'].startswith(PROTECTED_PREFIXES):
            return await self.app(scope, receive, send)
        for name, value in scope.get('headers', ()):
            if name == b'content-length':
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    return await self._reject(scope, receive, send)
        received, started, rejected = 0, False, False

        async def limited_receive():
            # Too much body: answer 413 ourselves, then tell the app the client went away
            # (the app's own error handling would otherwise turn this into a 400).
            nonlocal received, rejected
            if rejected:
                return {'type': 'http.disconnect'}
            message = await receive()
            if message['type'] == 'http.request':
                received += len(message.get('body', b''))
                if received > self.max_bytes:
                    rejected = True
                    if not started:
                        await self._reject(scope, receive, send)
                    return {'type': 'http.disconnect'}
            return message

        async def guarded_send(message):
            nonlocal started
            if rejected:                                  # the 413 has already been sent
                return
            if message['type'] == 'http.response.start':
                started = True
            await send(message)
        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not rejected:
                raise

    async def _reject(self, scope, receive, send):
        response = JSONResponse(status_code=413, headers={'Cache-Control': 'no-store'},
                                content={'detail': 'The request is too large.',
                                         'error': 'too_large'})
        await response(scope, receive, send)


# ---------------------------------------------------------------- wiring
def install(app: FastAPI, auth_service=None):
    """Add the routes, error handling, size limit and per-IP limit to `app`.
    auth_service: use this service (tests); default: built from app.state.settings on
    first use."""
    app.state.auth_service = auth_service
    app.state.api_limiter = SlidingWindowLimiter()
    app.add_exception_handler(AuthError, lambda request, err: _error_response(err))
    app.add_middleware(BodySizeLimit)
    app.include_router(auth)
    app.include_router(admin)
