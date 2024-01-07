import unittest
from unittest.mock import MagicMock
from app import crud

class TestCrudFunctions(unittest.TestCase):
    def test_create_user(self):
        # Arrange
        db_mock = MagicMock()
        user_data = {"username": "test_user", "password": "test_password"}

        # Act
        created_user = crud.create_user(db=db_mock, user=user_data)

        # Assert
        self.assertEqual(created_user.username, user_data["username"])

    def test_get_user_by_username(self):
        # Arrange
        db_mock = MagicMock()
        user_data = {"username": "test_user", "password": "test_password"}
        created_user = crud.create_user(db=db_mock, user=user_data)

        # Act
        retrieved_user = crud.get_user_by_username(db=db_mock, username=user_data["username"])

        # Assert
        self.assertEqual(retrieved_user, created_user)

    def test_verify_password(self):
        # Arrange
        password = "test_password"
        hashed_password = crud.hash_password(password)

        # Act
        is_verified = crud.verify_password(raw_password=password, hashed_password=hashed_password)

        # Assert
        self.assertTrue(is_verified)

    # Додайте інші тести для інших функцій

if __name__ == '__main__':
    unittest.main()
