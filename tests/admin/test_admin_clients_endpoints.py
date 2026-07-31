from unittest import mock

import jwt
import pytest

from fence.config import config
from fence.models import User
from tests import utils


@pytest.fixture(autouse=True)
def mock_arborist_authorization(mock_arborist_requests):
    mock_arborist_requests(
        {"arborist/auth/request": {"POST": ({"auth": True}, 200)}}
    )


@pytest.fixture
def admin_user(db_session):
    user = db_session.query(User).filter_by(username="admin_user").first()
    if not user:
        db_session.add(User(username="admin_user", id="5678", is_admin=True))
        db_session.commit()


@pytest.fixture
def encoded_admin_jwt(admin_user, kid, rsa_private_key):
    headers = {"kid": kid}
    claims = utils.default_claims()
    claims["context"]["user"]["name"] = "admin_user@fake.com"
    claims["sub"] = "5678"
    claims["iss"] = config["BASE_URL"]
    claims["exp"] += 600
    claims["scope"].append("admin")
    return jwt.encode(
        claims, key=rsa_private_key, headers=headers, algorithm="RS256"
    )


def test_get_all_fence_clients(
    client,
    encoded_admin_jwt,
    oauth_client_with_client_credentials,
):
    """GET /clients/fence returns selectable clients without credentials."""
    response = client.get(
        "/admin/clients/fence",
        headers={"Authorization": "Bearer " + encoded_admin_jwt},
    )

    assert response.status_code == 200
    fence_client = next(
        item
        for item in response.json
        if item["client_id"] == oauth_client_with_client_credentials.client_id
    )
    assert fence_client == {
        "client_id": oauth_client_with_client_credentials.client_id,
        "name": "testclient-with-client-credentials",
        "description": "",
    }
    assert "client_secret" not in fence_client


def test_get_all_fence_clients_requires_admin(client):
    response = client.get("/admin/clients/fence")

    assert response.status_code == 401


def test_create_client_skips_client_already_in_arborist(
    client,
    encoded_admin_jwt,
    oauth_client_with_client_credentials,
):
    client_id = oauth_client_with_client_credentials.client_id

    with mock.patch.object(
        client.application.arborist,
        "get_client",
        return_value={"clientID": client_id},
    ), mock.patch.object(
        client.application.arborist, "create_client"
    ) as create_client:
        response = client.post(
            "/admin/clients",
            json={"client_id": client_id, "policy_names": []},
            headers={"Authorization": "Bearer " + encoded_admin_jwt},
        )

    assert response.status_code == 200
    assert response.json == "Success"
    create_client.assert_not_called()


def test_create_client_creates_client_missing_from_arborist(
    client,
    encoded_admin_jwt,
    oauth_client_with_client_credentials,
):
    client_id = oauth_client_with_client_credentials.client_id

    with mock.patch.object(
        client.application.arborist,
        "get_client",
        return_value=None,
    ), mock.patch.object(
        client.application.arborist, "create_client"
    ) as create_client:
        response = client.post(
            "/admin/clients",
            json={"client_id": client_id, "policy_names": []},
            headers={"Authorization": "Bearer " + encoded_admin_jwt},
        )

    assert response.status_code == 200
    assert response.json == "Success"
    create_client.assert_called_once_with(client_id, [])
