"""Print reproducible HTTP observations from the vulnerable and fixed APIs."""

from sys import stdout

from fastapi.testclient import TestClient
from httpx import Response

from examples.idor_app import make_app


def get_order(client: TestClient, order_id: int, token: str | None) -> Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.get(f"/orders/{order_id}", headers=headers)


def main() -> None:
    with (
        TestClient(make_app(vulnerable=True)) as vulnerable,
        TestClient(make_app()) as fixed,
    ):
        cases = (
            ("vulnerable_a_own", vulnerable, 101, "demo-a", 200, 101),
            ("vulnerable_a_foreign", vulnerable, 202, "demo-a", 200, 202),
            ("fixed_a_own", fixed, 101, "demo-a", 200, 101),
            ("fixed_a_foreign", fixed, 202, "demo-a", 404, None),
            ("fixed_b_own", fixed, 202, "demo-b", 200, 202),
            ("fixed_missing_order", fixed, 999, "demo-a", 404, None),
            ("fixed_anonymous", fixed, 101, None, 401, None),
            ("fixed_invalid_token", fixed, 101, "invalid", 401, None),
        )
        for name, client, order_id, token, expected_status, expected_id in cases:
            response = get_order(client, order_id, token)
            observed_id = response.json().get("id")
            if (response.status_code, observed_id) != (expected_status, expected_id):
                raise AssertionError(f"{name}: unexpected response {response.status_code}, {response.text}")
            stdout.write(f"{name}: status={response.status_code} order_id={observed_id}\n")


if __name__ == "__main__":
    main()
