from abc import ABC, abstractmethod


class BaseRequest(ABC):
    """
    Base class for implement external interface for all API auth types requests.
    """

    def make_request(self):
        pass

    @abstractmethod
    def _auth_request_data(self) -> dict:
        pass

    def _make_auth(self):
        pass

    def _login(self):
        pass


class PersonAuthData(BaseRequest):
    def __init__(self, login: str, password: str):
        self.__login = login
        self.__password = password

    def _auth_request_data(self) -> dict:
        pass


class CustomerRequest(PersonAuthData):
    pass


class AdministratorRequest(PersonAuthData):
    pass


class ApiKeyRequest(BaseRequest):
    def __init__(self, api_key: str, api_secret: str):
        self.__api_key = api_key
        self.__api_secret = api_secret

    def _auth_request_data(self) -> dict:
        pass
