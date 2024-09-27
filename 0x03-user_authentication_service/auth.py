import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash password using bcrypt

        Args:
            password (str): The password to hash

        Returns:
            bytes: The hashed password
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """Registers a user if the email is not already in use

        Args:
            email (str): The user's email
            password (str): The user's password

        Returns:
            User: The newly created User object

        Raises:
            ValueError: If the email is already registered
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email,
                                         hashed_password.decode('utf-8'))
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates user login by checking if the email
        exists and password matches

        Args:
            email (str): User's email
            password (str): User's plaintext password

        Returns:
            bool: True if login is valid, False otherwise
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'),
                              user.hashed_password.encode('utf-8')):
                return True
        except NoResultFound:
            return False
        return False
