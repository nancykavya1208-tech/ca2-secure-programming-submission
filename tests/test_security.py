import os
import sys
import yaml
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app


def load_policies():
    #Loading security policies from YAML file.
    policy_path = os.path.join(os.path.dirname(__file__), "policy.yaml")
    with open(policy_path, "r") as f:
        data = yaml.safe_load(f)
    return data["policies"]


@pytest.fixture
def client():
    #Creating a test client with temporary database.
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "test-secret-key")
    with app.test_client() as client:
        yield client

@pytest.mark.parametrize("policy", load_policies())
def test_access_control(policy, client):
    #Parametrized access control tests from policy matrix (AC-01 to AC-06).
    method = policy["method"].lower()
    path = policy["path"]
    expected_status = policy["expected_status"]
    expected_contains = policy.get("expected_contains", [])
    expected_not_contains = policy.get("expected_not_contains", [])
    data = policy.get("data", None)

    # Authenticate if credentials provided
    if policy["user"] and policy["password"]:
        resp = client.post("/login", data={
            "username": policy["user"],
            "password": policy["password"]
        }, follow_redirects=True)
        assert resp.status_code == 200, f"Login failed for {policy['user']}"

    # Make request
    if method == "get":
        resp = client.get(path)
    elif method == "post":
        resp = client.post(path, data=data)
    else:
        pytest.skip(f"Unsupported method: {method}")

    # Assert status code
    assert resp.status_code == expected_status, \
        f"{policy['id']}: Expected {expected_status}, got {resp.status_code} for {method.upper()} {path}"
    # Assert content presence
    body = resp.get_data(as_text=True)
    for text in expected_contains:
        assert text in body, f"{policy['id']}: Expected '{text}' in response body"
    # Assert content absence
    for text in expected_not_contains:
        assert text not in body, f"{policy['id']}: Did not expect '{text}' in response body"
