"""Reproducible request sequence: print actual response statuses and object IDs."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fastapi.testclient import TestClient
from idor_app import make_app


def request(client: TestClient, order_id: int, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get(f"/orders/{order_id}", headers=headers)


def main():
    vulnerable = TestClient(make_app(vulnerable=True))
    fixed = TestClient(make_app())
    observations = [
        ("vulnerable_a_own", request(vulnerable, 101, "demo-a"), 200, 101),
        ("vulnerable_a_foreign", request(vulnerable, 202, "demo-a"), 200, 202),
        ("fixed_a_own", request(fixed, 101, "demo-a"), 200, 101),
        ("fixed_a_foreign", request(fixed, 202, "demo-a"), 404, None),
        ("fixed_b_own", request(fixed, 202, "demo-b"), 200, 202),
        ("fixed_missing_order", request(fixed, 999, "demo-a"), 404, None),
        ("fixed_anonymous", request(fixed, 101, None), 401, None),
        ("fixed_invalid_token", request(fixed, 101, "invalid"), 401, None),
    ]
    for name, response, expected_status, expected_id in observations:
        observed_id = response.json().get("id")
        assert (response.status_code, observed_id) == (expected_status, expected_id), name
        print(f"{name}: status={response.status_code} order_id={observed_id}")


if __name__ == "__main__":
    main()
