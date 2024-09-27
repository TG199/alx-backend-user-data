import uuid
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound, InvalidRequestError
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

    def _generate_uuid() -> str:
        """Generates a new UUID and returns its string representation.

        This method is private to the auth module.

        Returns:
            str: String representation of a UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """Creates a new session for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The session ID.

        Raises:
            NoResultFound: If the user is not found in the database.
        """
        user = self._db.find_user_by(email=email)

        session_id = self._generate_uuid()

        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str):
        """Retrieve a user based on the session ID.

        Args:
            session_id (str): The session ID of the user.

        Returns:
            User or None: The user object if found, else None.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int):
        """Destroy the user's session by setting session_id to None.

        Args:
            user_id (int): The ID of the user whose session is to be destroyed.

        Returns:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except (NoResultFound, InvalidRequestError) as e:
            raise ValueError(f"Error updating session \
                             for user ID {user_id}: {e}")

    def get_reset_password_token(self, email: str) -> str:
        """Generate a reset password token for the user.

        Args:
            email (str): The email of the user.

        Returns:
            str: The generated reset token.

        Raises:
            ValueError: If the user does not exist.
        """

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"User with email {email} does not exist.")

        reset_token = str(uuid.uuid4())

        user.reset_token = reset_token
        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def _hash_password(self, password: str) -> bytes:
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def update_password(self, reset_token: str, password: str) -> None:
        """Update the user's password using the reset token.

        Args:
            reset_token (str): The reset token for the user.
            password (str): The new password to set.

        Raises:
            ValueError: If the user does not exist.
        """

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token.")

        hashed_password = self._hash_password(password)

        self._db.update_user(user.id,
                             hashed_password=hashed_password, reset_token=None)
