#!/usr/bin/env python3
""" Auth Model"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
import bcrypt
from user import Base


class DB:
    """DB class with hashing method"""

    def __init__(self) -> None:
        """Initialize a new DB instance"""
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    def _hash_password(self, password: str) -> bytes:
        """Hashes a password using bcrypt with a salt
        
        Args:
            password (str): The password to hash
        
        Returns:
            bytes: The hashed password in bytes
        """
        salt = bcrypt.gensalt()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed_password
