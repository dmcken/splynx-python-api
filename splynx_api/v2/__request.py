from abc import ABC, abstractmethod
from enum import Enum
from urllib.parse import urlencode

import requests

from .__exceptions import ApiCallError

AUTH_TYPE_API_KEY = 'api_key'
AUTH_TYPE_CUSTOMER = 'customer'
AUTH_TYPE_SESSION = 'session'
AUTH_TYPE_ADMIN = 'admin'


class RequestMethods(Enum):
    METHOD_GET = 'get'
    METHOD_POST = 'post'
    METHOD_PUT = 'put'
    METHOD_delete = 'delete'


class BaseRequest(ABC):
    """
    Base class for implement external interface for all API auth types requests.
    """

    TOKEN_URL = 'admin/auth/tokens'

    def __init__(self, splynx_domain: str, debug: bool = False):
        if not splynx_domain:
            raise ValueError("You must enter Splynx url")

        self._splynx_domain = splynx_domain.rstrip('/')

        self.__access_token = None
        self.__access_token_expiration = None
        self.__refresh_token = None
        self.__refresh_token_expiration = None
        self.__permissions = None

        self.__response = None
        self.__result = None

        self.__debug = debug

    def make_request(self, method: str, path: str, params: dict = None, content_type: str = 'application/json',
                     skip_login: bool = False, entity_id=None):
        self._debug()
        request_url = self.__create_url(path, entity_id)

        method = method.lower()
        headers = self.__get_request_header(content_type, skip_login)

        try:
            response = self.__do_requests(request_url, method, headers, params)
        except requests.exceptions.RequestException as exception:
            self.__response = {}
            self.__result = False
            raise ApiCallError("Error while make API call. Error: {}".format(str(exception)))

        self.__process_response(response)
        # todo add token renew

        return self.__result

    def __create_url(self, path: str, entity_id=None) -> str:
        request_url = self._splynx_domain + '/api/2.0/' + path.lstrip('/')

        if entity_id is not None:
            request_url = request_url.rstrip('/') + "/" + str(entity_id)

        return request_url

    def __do_requests(self, request_url: str, method: str, headers: dict, params: dict = None):
        self._debug("{}: {}".format(method, request_url))
        self._debug("Params: {}".format(str(params)))
        if method == 'post' or method == 'put':
            return requests.request(method, request_url, headers=headers, json=params)
        else:
            if params:
                request_url = request_url + "?" + urlencode(params)

            return requests.request(method, request_url, headers=headers)

    def __process_response(self, response: requests.Response):
        self._debug("Response test: {}".format(response.text))
        self._debug("Response code: {}".format(response.status_code))

        if not response.text:
            self.__response = {}
        else:
            self.__response = response.json()

        self.__result = self.__get_result_by_status_code(response)

    @staticmethod
    def __get_result_by_status_code(response: requests.Response) -> bool:
        if (response.request.method == 'GET' or response.request.method == 'OPTION') and response.status_code == 200:
            return True

        if (response.request.method == 'DELETE' or response.request.method == 'HEAD') and response.status_code == 204:
            return True

        if response.request.method == 'POST' and response.status_code == 201:
            return True

        if response.request.method == 'PUT' and response.status_code == 202:
            return True

        return False

    def __get_request_header(self, content_type: str = 'application/json', skip_login: bool = False) -> dict:
        return {
            'authorization': self.__get_auth_header(skip_login),
            'content-type': content_type,
            'user-agent': 'Splynx Python API v2'
        }

    def __get_auth_header(self, skip_login: bool = False) -> str:
        if skip_login is False and self.__access_token is None:
            self.login()

        return "Splynx-EA (access_token=" + str(self.__access_token) + ")"

    def login(self):
        self.make_request("POST", self.TOKEN_URL, params=self._auth_request_data(), skip_login=True)

        if self.__result is False:
            return False

        self.auth_data = self.__response
        return True

    def logout(self):
        response = self.make_request("DELETE", self.TOKEN_URL, entity_id=self.__refresh_token)

        self.__access_token = None
        self.__access_token_expiration = None
        self.__refresh_token = None
        self.__refresh_token_expiration = None
        self.__permissions = None

        return response

    @abstractmethod
    def _auth_request_data(self) -> dict:
        pass

    @property
    def auth_data(self) -> dict:
        return {
            'access_token': self.__access_token,
            'access_token_expiration': self.__access_token_expiration,
            'refresh_token': self.__refresh_token,
            'refresh_token_expiration': self.__refresh_token_expiration,
            'permissions': self.__permissions,
        }

    @auth_data.setter
    def auth_data(self, data: dict):
        self.__access_token = data.get('access_token')
        self.__access_token_expiration = data.get('access_token_expiration')
        self.__refresh_token = data.get('refresh_token')
        self.__refresh_token_expiration = data.get('refresh_token_expiration')
        self.__permissions = data.get('permissions')

    @property
    def result(self):
        return self.__result

    @property
    def response(self):
        return self.__response

    @property
    def debug(self):
        return self.__debug

    @debug.setter
    def debug(self, value: bool):
        self.__debug = value

    def _debug(self, message: str = ""):
        if self.__debug:
            print(message)


class PersonRequest(BaseRequest):
    def __init__(self, splynx_domain: str, login: str, password: str, debug: bool = False):
        self._login = login
        self._password = password
        super().__init__(splynx_domain, debug=debug)

    def _auth_request_data(self) -> dict:
        return {
            'login': self._login,
            'password': self._password,
        }


class CustomerRequest(PersonRequest):
    def _auth_request_data(self) -> dict:
        auth_data = super()._auth_request_data()
        auth_data['auth_type'] = AUTH_TYPE_CUSTOMER
        return auth_data


class AdministratorRequest(PersonRequest):
    def _auth_request_data(self) -> dict:
        auth_data = super()._auth_request_data()
        auth_data['auth_type'] = AUTH_TYPE_ADMIN
        return auth_data


class ApiKeyRequest(BaseRequest):
    def __init__(self, splynx_domain: str, api_key: str, api_secret: str, debug: bool = False):
        self._api_key = api_key
        self._api_secret = api_secret
        super().__init__(splynx_domain, debug=debug)

    def _auth_request_data(self) -> dict:
        return {
            'auth_type': AUTH_TYPE_API_KEY,
            'api_key': self._api_key,
            'signature': self._api_secret,  # todo make signature
        }
