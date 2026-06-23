# FraudGuard ML (MVP)

Backend: FastAPI + SQLite. Frontend: TBD.

## Run backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

## API quickstart

1. Register
```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"secret"}'
```

2. Login
```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"secret"}'
```
Copy `access_token` from the response.

3. Score a transaction
```bash
TOKEN=... # paste token
curl -X POST http://127.0.0.1:8000/fraud/score \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"amount":1200.0, "mcc":"7995", "ip":"1.1.1.1", "velocity_1min":3, "timezone_mismatch":true}'
```

4. View alerts
```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/fraud/alerts
```

## OTP Challenge Flow (MFA)

1. Trigger a challenge by scoring a risky transaction (decision may be `challenge`). Note the `transaction_id` from `/fraud/score`.

2. Initiate OTP
```bash
curl -X POST http://127.0.0.1:8000/fraud/otp/init \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"transaction_id": TRANSACTION_ID}'
```
Response returns `{ code: "xxxxxx" }` for demo/testing.

3. Verify OTP
```bash
curl -X POST http://127.0.0.1:8000/fraud/otp/verify \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"transaction_id": TRANSACTION_ID, "code": "XXXXXX"}'
```

## Admin: Roles and Audit Logs

1. List users
```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/admin/users
```

2. Update a user's role (admin only)
```bash
curl -X POST http://127.0.0.1:8000/admin/role \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_id": 1, "role": "admin"}'
```

3. View audit logs (admin/manager)
```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/admin/audit
```
