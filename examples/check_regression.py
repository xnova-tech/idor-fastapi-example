"""Isolated regression checks with negative control against vulnerable behavior."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import io
import unittest
from fastapi.testclient import TestClient
from idor_app import current_user, make_app


class AuthorizationChecks(unittest.TestCase):
    def setUp(self):
        self.app = make_app()
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.dependency_overrides.clear()
        self.client.close()

    def get(self, order_id, token="demo-a"):
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        return self.client.get(f"/orders/{order_id}", headers=headers)

    def test_owner_reads_own_order(self):
        r = self.get(101)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["owner_id"], "A")

    def test_other_user_cannot_read_order(self):
        r = self.get(202)
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Headphones", r.text)

    def test_other_owner_reads_own_order(self):
        r = self.get(202, "demo-b")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["owner_id"], "B")

    def test_missing_order_returns_same_response_as_foreign(self):
        self.assertEqual(self.get(202).json(), self.get(999).json())

    def test_anonymous_is_unauthorized(self):
        self.assertEqual(self.get(101, None).status_code, 401)

    def test_invalid_token_is_unauthorized(self):
        self.assertEqual(self.get(101, "invalid").status_code, 401)

    def test_dependency_override_is_scoped_and_cleared(self):
        self.app.dependency_overrides[current_user] = lambda: "B"
        self.assertEqual(self.get(202, "demo-a").status_code, 200)
        self.app.dependency_overrides.clear()
        self.assertEqual(self.get(202, "demo-a").status_code, 404)

    def test_negative_control_confirms_vulnerable_variant_leaks(self):
        with TestClient(make_app(vulnerable=True)) as client:
            r = client.get("/orders/202", headers={"Authorization": "Bearer demo-a"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["owner_id"], "B")

    def test_vulnerable_variant_rejects_non_testclient(self):
        with TestClient(make_app(vulnerable=True), client=("external", 1234)) as client:
            r = client.get("/orders/202", headers={"Authorization": "Bearer demo-a"})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("Headphones", r.text)


if __name__ == "__main__":
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AuthorizationChecks)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(f"regression: {result.testsRun} tests passed")
