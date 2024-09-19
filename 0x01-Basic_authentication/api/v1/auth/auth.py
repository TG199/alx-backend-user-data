#!/usr/bin/env python3
""" Basic auth module"""
from typing import List, TypeVar
from flask import request


class Auth:
    """ Auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that
            don't require authentication.

        Returns:
            bool: False for now, authentication logic will be added later.
        """
        if path is None:
            return True

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path += '/'

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.

        Args:
            request (Flask.request): The Flask request object.

        Returns:
            str: None for now, will be implemented later.
        """
        if request is None:
            return None

        if not request.headers.get('Authorization'):
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar:
        """
        Retrieves the current user from the request.

        Args:
            request (Flask.request): The Flask request object.

        Returns:
            TypeVar('User'): None for now, user retrieval
            logic will be added later.
        """
        return None
