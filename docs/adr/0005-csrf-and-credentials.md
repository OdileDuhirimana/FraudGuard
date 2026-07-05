# ADR 0005: No CSRF protection needed — `allow_credentials=False`

## Status
Accepted

## Context
The code review flagged `SEC-07`: `allow_credentials=True` was set on
`CORSMiddleware` in `main.py` with no CSRF protection anywhere in the
codebase and no comment explaining why that combination was considered
safe. Read cold, that is a legitimate finding — `allow_credentials=True`
is exactly the precondition that makes CSRF exploitable, because it tells
browsers to attach ambient credentials (cookies, HTTP auth) to cross-origin
requests and to expose the response back to the calling page.

The relevant fact this project's code never stated explicitly: FraudGuard
has no cookie-based session or any other ambient browser credential
anywhere. Every authenticated request must present a JWT explicitly in the
`Authorization: Bearer <token>` header (`auth.py`'s
`OAuth2PasswordBearer(tokenUrl="/v1/auth/login")`, checked in
`get_current_user`). A malicious page on another origin cannot make a
victim's browser attach a header it doesn't already hold and cannot read
from browser-managed storage across origins — there is no ambient
credential for a forged cross-site request to ride on. CSRF, as a class of
attack, targets *ambient* credential transport (cookies), not bearer
tokens a client must read from storage and attach itself.

## Decision
1. `allow_credentials` is now `False` (`main.py`). This was previously
   `True` with no cookie-based session ever depending on it — the setting
   was doing nothing except widening the CORS attack surface for no
   functional benefit.
2. No CSRF token mechanism (double-submit cookie, synchronizer token) is
   added, because there is no session-cookie transport for CSRF to exploit
   in the first place. Adding CSRF tokens to a bearer-token-only API would
   be defense against an attack this architecture cannot suffer, not real
   protection.
3. If a future browser-based frontend introduces a cookie-based session
   (e.g. an httpOnly refresh-token cookie for the logout/refresh flow),
   this decision must be revisited at that time — `allow_credentials` would
   need to become `True` again scoped to that specific flow, and CSRF
   protection (SameSite cookie attributes at minimum, a token-based scheme
   if broader browser support is required) would become a real
   requirement, not a moot one.

## Consequences
- Closes SEC-07 by removing the unsafe combination rather than adding a
  CSRF mechanism this API's auth model doesn't need — the smaller, more
  honest fix.
- `CORS_ALLOWED_ORIGINS` continues to fail closed and reject wildcards
  (ADR 0003) independently of this decision — CORS misconfiguration and
  CSRF are related but distinct risks, and this ADR only addresses the
  latter.
- This decision is coupled to "no cookie-based session exists." Any change
  that introduces one (see refresh-token/logout work) must re-open this
  ADR.
