#!/usr/bin/env python3
""" Basic Auth Module
"""
import base64
from api.v1.auth.auth import Auth
from typing import TypeVar


class BasicAuth(Auth):
    """BasicAuth class that inherits from Auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization
        header for Basic Authentication.

        :param authorization_header: The Authorization
        header from the request.
        :return: The Base64 encoded part of the Authorization
        header or None.
        """

        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
                                            self,
                                            base64_authorization_header:
                                            str) -> str:
        """
        Decodes the Base64 part of
        the Authorization header.

        :param base64_authorization_header: Base64 encoded string
        from the Authorization header.
        :return: Decoded string as UTF-8 or None if invalid.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:

            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
                                self,
                                decoded_base64_authorization_header:
                                str) -> str:
        """
        Extracts the user email and password from
        the decoded Base64 Authorization header.

        :param decoded_base64_authorization_header: Decoded Base64 string.
        :return: Tuple containing user email and
        password, or (None, None) if invalid.
        """

        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(':', 1)

        return email, password

    def user_object_from_credentials(self,
                                     user_email:
                                     str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on
        the provided email and password.

        :param user_email: The user's email.
        :param user_pwd: The user's password.
        :return: User instance if valid credentials, otherwise None.
        """

        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})

        if not users or len(users) == 0:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request.

        :param request: The Flask request object.
        :return: User instance or None if not found.
        """

        auth_header = self.authorization_header(request)

        base64_auth_header = self.extract_base64_authorization_header
        (auth_header)

        decoded_auth_header = self.decode_base64_authorization_header
        (base64_auth_header)

        email, password = self.extract_user_credentials(decoded_auth_header)

        user = self.user_object_from_credentials(email, password)

        return user
