#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database

        Args:
            email (str): The email of the user
            hashed_password (str): The hashed password of the user

        Returns:
            User: The created User object
        """
        new_user = User(email=email, hashed_password=hashed_password)

        self._session.add(new_user)
        self._session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find the first user based on arbitrary keyword arguments

        Args:
            **kwargs: Arbitrary keyword arguments for filtering the query

        Returns:
            User: The first User object matching the criteria

        Raises:
            NoResultFound: If no user is found
            InvalidRequestError: If invalid query arguments are passed
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()

            if user is None:
                raise NoResultFound

            return user

        except InvalidRequestError:
            raise InvalidRequestError("Invalid query argument")
        except NoResultFound:
            raise NoResultFound("No user found with the provided filters")

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update user's attributes based on the passed keyword arguments

        Args:
            user_id (int): The ID of the user to be updated
            **kwargs: Arbitrary keyword arguments
            representing the attributes to be updated

        Returns:
            None

        Raises:
            ValueError: If any of the keyword arguments
            do not correspond to valid user attributes
        """
        try:
            user = self.find_user_by(id=user_id)

            for key, value in kwargs.items():
                if not hasattr(user, key):
                    raise ValueError(f"{key} is not a valid attribute of User")
                setattr(user, key, value)

            self._session.commit()

        except NoResultFound:
            raise NoResultFound(f"User with id {user_id} not found")
        except InvalidRequestError:
            raise InvalidRequestError("Invalid request while updating user")
