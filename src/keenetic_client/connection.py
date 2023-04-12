# -*- coding: utf-8 -*-
import logging
import requests
import hashlib
from requests.exceptions import ConnectionError, RequestException, Timeout
from .exceptions import ConnectionException, AuthenticationException, CommandException

_LOGGER = logging.getLogger(__name__)

class Connection:
    """Maintains a connection to a router."""

    def __init__(self, host: str, port: int, username: str, password: str, timeout: int = 30):
        """Initialize the connection properties."""
        self._session: requests.Session | None = None
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._endpoint = f'http://{host}:{port}'


    def connect(self):
        """Connect to the server."""
        self._session = requests.Session()


    def disconnect(self):
        """Disconnect the current connection."""
        self._session.close();
        self._session = None


    @property
    def connected(self):
        return self._session is not None


    def command_read(self, uri):
        """Run a command through a connection.
         Connect to the server if not currently connected, otherwise
         use the existing connection.
        """
        if not self._session:
            self.connect()
        return self.__get(uri)


    def command_write(self, uri: str, json):
        if not self._session:
            self.connect()
        return self.__post(uri, json)


    def command_delete(self, uri: str):
        if not self._session:
            self.connect()
        return self.__delete(uri)


    def __auth(self):
        response = self._session.get(f'{self._endpoint}/auth', timeout = self._timeout)
        if response.status_code == 401:
            realm = response.headers['X-NDM-Realm']
            password = f'{self._username}:{realm}:{self._password}'
            password = hashlib.md5(password.encode('utf-8'))
            challenge = response.headers['X-NDM-Challenge']
            password = challenge + password.hexdigest()
            password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            response = self._session.post(
                f'{self._endpoint}/auth',
                json = {'login': self._username, 'password': password},
                timeout = self._timeout)
        return response.status_code == 200


    def __get(self, uri: str):
        try:
            response = self._session.get(self._endpoint + uri, timeout = self._timeout)
            if response.status_code != 200:
                if response.status_code != 401:
                    raise CommandException()
                if self.__auth() is False:
                    raise AuthenticationException()
                response = self._session.get(self._endpoint + uri, timeout = self._timeout)
                if response.status_code != 200:
                    raise CommandException()
            return response.json()
        except ConnectionError as exc:
            raise ConnectionException from exc
        except RequestException as exc:
            raise CommandException from exc


    def __post(self, uri: str, data):
        try:
            response = self._session.post(self._endpoint + uri, json = data, timeout = self._timeout)
            if response.status_code != 200:
                if response.status_code != 401:
                    raise CommandException()
                if self.__auth() is False:
                    raise AuthenticationException()
                response = self._session.post(self._endpoint + uri, json = data, timeout = self._timeout)
                if response.status_code != 200:
                    raise CommandException()
        except ConnectionError as exc:
            raise ConnectionException from exc
        except RequestException as exc:
            raise CommandException from exc


    def __delete(self, uri: str):
        try:
            response = self._session.delete(f'{self._endpoint}{uri}', timeout = self._timeout)
            if response.status_code != 200:
                if response.status_code != 401:
                    raise CommandException()
                if self.__auth() is False:
                    raise AuthenticationException()
                response = self._session.post(f'{self._endpoint}{uri}', timeout = self._timeout)
                if response.status_code != 200:
                    raise CommandException()
        except ConnectionError as exc:
            raise ConnectionException from exc
        except RequestException as exc:
            raise CommandException from exc
