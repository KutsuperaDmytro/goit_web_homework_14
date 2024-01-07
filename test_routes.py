import pytest
from fastapi.testclient import TestClient
import main as app

@pytest.fixture
def client():
    return TestClient(app)

def test_protected_route_without_token(client):
    response = client.get("/protected")
    assert response.status_code == 401  # Перевірте, чи відсутній токен доступу

def test_protected_route_with_valid_token(client):
    # Припускаємо, що маємо дійсний токен доступу
    valid_token = "your_valid_access_token"
    headers = {"Authorization": f"Bearer {valid_token}"}

    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "This is a protected route"
