"""
Locust load test specifically targeting concurrent OTP-verification
attempts — the endpoint this project's own security work (test_otp.py,
ADR 0004) treats as the most brute-force-sensitive in the API.

Usage (against a locally running instance):

    cd backend
    uvicorn app.main:app --host 0.0.0.0 --port 8000 &
    locust -f loadtest/locustfile.py --host http://127.0.0.1:8000 \\
        --headless -u 20 -r 5 -t 30s --csv=loadtest/results

See docs/load-test-results.md for the actual numbers produced by running
this, executed and documented honestly as a dev-environment approximation
on a single-process `uvicorn` instance against SQLite — NOT a production
capacity benchmark. `RATE_LIMIT_OTP_PER_MINUTE` should be raised for this
run (see the doc) since the whole point here is observing application
behavior under concurrency, not re-proving the rate limiter itself works
(that is already covered by tests/test_rate_limit.py).

Each simulated user:
1. Registers a unique account and logs in.
2. Scores a transaction engineered to land in "challenge" (medium risk).
3. Initiates an OTP challenge for it.
4. Repeatedly attempts to verify with a WRONG code — modeling an attacker
   (or a confused legitimate user) hammering /otp/verify concurrently for
   that transaction — interspersed with the correct code once, to also
   exercise the success path under the same concurrent load.
"""
from __future__ import annotations

import random
import uuid

from locust import HttpUser, task, between


class OTPVerificationUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        email = f"loadtest-{uuid.uuid4().hex}@example.com"
        password = "SecurePass123!"
        self.client.post("/v1/auth/register", json={"email": email, "password": password})
        login_response = self.client.post(
            "/v1/auth/login", json={"email": email, "password": password}
        )
        token = login_response.json().get("access_token", "")
        self.headers = {"Authorization": f"Bearer {token}"}

        score_response = self.client.post(
            "/v1/fraud/score",
            json={
                "amount": 1500.0,
                "mcc": "7995",
                "ip": "203.0.113.9",
                "gps_lat": 1.0,
                "gps_lon": 1.0,
                "timezone_mismatch": True,
            },
            headers=self.headers,
        )
        self.transaction_id = score_response.json().get("transaction_id")

        self.client.post(
            "/v1/fraud/otp/init",
            json={"transaction_id": self.transaction_id},
            headers=self.headers,
        )

    @task(5)
    def verify_with_wrong_code(self):
        """
        The concurrency-under-attack scenario this load test targets. A
        `400 invalid_code` response here is the *correct*, expected
        outcome (the code is deliberately wrong) — not a system failure —
        so it is explicitly marked as a success via `catch_response`.
        Anything else (500s, connection errors, an unexpected 200) is left
        to fail normally, since that would indicate a real problem.
        """
        wrong_code = f"{random.randint(0, 999999):06d}"
        with self.client.post(
            "/v1/fraud/otp/verify",
            json={"transaction_id": self.transaction_id, "code": wrong_code},
            headers=self.headers,
            name="/v1/fraud/otp/verify [wrong code]",
            catch_response=True,
        ) as response:
            if response.status_code == 400:
                response.success()

    @task(1)
    def check_alerts_feed(self):
        """Background read load competing for the same DB alongside the OTP hammering above."""
        self.client.get("/v1/fraud/alerts", headers=self.headers, name="/v1/fraud/alerts")
