#!/usr/bin/env python3
""" Basic Auth Module
"""
import base64
from api.v1.auth.auth import Auth


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
