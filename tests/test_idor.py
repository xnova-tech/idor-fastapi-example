"""Object-authorization regression tests with a vulnerable negative control."""

from collections.abc import Iterator

import pytest
from examples.idor_app import current_user, make_app
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response


@pytest.fixture
def app() -> FastAPI:
    return make_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as http:
        yield http


def get_order(client: TestClient, order_id: int, token: str | None = "demo-a") -> Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.get(f"/orders/{order_id}", headers=headers)


def test_owner_reads_own_order(client: TestClient) -> None:
    response = get_order(client, 101)
    assert response.status_code == 200
    assert response.json()["owner_id"] == "A"


def test_other_user_cannot_read_order(client: TestClient) -> None:
    response = get_order(client, 202)
    assert response.status_code == 404
    assert "Headphones" not in response.text


def test_other_owner_reads_own_order(client: TestClient) -> None:
    response = get_order(client, 202, "demo-b")
    assert response.status_code == 200
    assert response.json()["owner_id"] == "B"


def test_missing_order_matches_foreign_order(client: TestClient) -> None:
    foreign = get_order(client, 202)
    missing = get_order(client, 999)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_anonymous_request_is_unauthorized(client: TestClient) -> None:
    assert get_order(client, 101, None).status_code == 401


def test_invalid_token_is_unauthorized(client: TestClient) -> None:
    assert get_order(client, 101, "invalid").status_code == 401


def test_dependency_override_is_cleared(app: FastAPI, client: TestClient) -> None:
    app.dependency_overrides[current_user] = lambda: "B"
    assert get_order(client, 202).status_code == 200

    app.dependency_overrides.clear()
    assert get_order(client, 202).status_code == 404


def test_vulnerable_variant_exposes_foreign_order() -> None:
    with TestClient(make_app(vulnerable=True)) as client:
        response = get_order(client, 202)
    assert response.status_code == 200
    assert response.json()["owner_id"] == "B"


def test_vulnerable_variant_rejects_external_client() -> None:
    with TestClient(make_app(vulnerable=True), client=("external", 1234)) as client:
        response = get_order(client, 202)
    assert response.status_code == 403
    assert "Headphones" not in response.text


def test_fixed_variant_allows_external_client_to_read_own_order() -> None:
    with TestClient(make_app(), client=("external", 1234)) as client:
        response = get_order(client, 101)
    assert response.status_code == 200
    assert response.json()["owner_id"] == "A"
