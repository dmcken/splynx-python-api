import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from datetime import datetime
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

        self._debug = debug

    def make_request(self, method: str, path: str, params: dict = None, content_type: str = 'application/json',
                     skip_login: bool = False, entity_id=None):
        """
        Method for make different http requests types.

        Method automatically login on system or you can do it manually.
        For manually usage you can use method login or set auth tokens from local storage.

        Usage:
            TODO

        :param str method: HTTP request methods names. Available methods: get, post, put, delete, option, head.
        :param str path: API path. See Splynx API doc https://splynx.docs.apiary.io/ .
        :param dict params: API call params.
        :param content_type: API call content type. Default value: `application/json`.
        :param skip_login: Flag for skipping authorization header.
        :param entity_id: Id of entity. For example: customer id.

        :return bool: api call result
        """
        self._debug_message()
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

        return self.__result

    def __create_url(self, path: str, entity_id=None) -> str:
        request_url = self._splynx_domain + '/api/2.0/' + path.lstrip('/')

        if entity_id is not None:
            request_url = request_url.rstrip('/') + "/" + str(entity_id)

        return request_url

    def __do_requests(self, request_url: str, method: str, headers: dict, params: dict = None):
        self._debug_message("{}: {}".format(method, request_url))
        self._debug_message("Params: {}".format(str(params)))
        if method == 'post' or method == 'put':
            return requests.request(method, request_url, headers=headers, json=params)
        else:
            if params:
                request_url = request_url + "?" + urlencode(params)

            return requests.request(method, request_url, headers=headers)

    def __process_response(self, response: requests.Response):
        self._debug_message("Response test: {}".format(response.text))
        self._debug_message("Response code: {}".format(response.status_code))

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

    def __renew_tokens(self):
        if self.__refresh_token_expiration > time.time() + 5 > self.__access_token_expiration:
            result = self.make_request("GET", self.TOKEN_URL, entity_id=self.__refresh_token, skip_login=True)
            if result:
                return False
            self.auth_data = self.__response

    def login(self):
        """
        Method for authorize on Splynx system API.

        This method make api call to Splynx system and generate API tokens.
        After you can save token into your storage an use in future, but this tokens has expiration time.
        See more details about Splynx API authorization on
        page: https://splynx.docs.apiary.io/#introduction/authentication/by-access-token

        Usage:
            TODO

        :return bool: Result of authorization.
        """
        self.make_request("POST", self.TOKEN_URL, params=self._auth_request_data(), skip_login=True)

        if self.__result is False:
            return False

        self.auth_data = self.__response
        return True

    def logout(self):
        """
        Method for authorize on Splynx system API.

        This method make api call to Splynx system and deactivate API token.
        See more details about Splynx API authorization on
        page: https://splynx.docs.apiary.io/#introduction/authentication/by-access-token

        Usage:
            TODO

        :return bool: Deactivate token result.
        """
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
        return self._debug

    @debug.setter
    def debug(self, value: bool):
        self._debug = value

    def _debug_message(self, message: str = ""):
        if self.debug:
            print(message)

    def api_call_get(self, path: str, entity_id=None, params: dict = None):
        return self.make_request('get', path, params=params, entity_id=entity_id)

    def api_call_delete(self, path: str, entity_id=None):
        return self.make_request('delete', path, entity_id=entity_id)

    def api_call_post(self, path: str, params: dict = None):
        return self.make_request('post', path, params)

    def api_call_put(self, path: str, params: dict = None):
        return self.make_request('put', path, params)

    def api_call_options(self, path: str):
        return self.make_request('options', path)

    def api_call_head(self, path: str):
        return self.make_request('head', path)


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
        super().__init__(splynx_domain, debug=debug)
        self._api_key = api_key
        self._api_secret = api_secret
        self.__nonce_v = None
        self.__nonce()

    def _auth_request_data(self) -> dict:
        return {
            'auth_type': AUTH_TYPE_API_KEY,
            'key': self._api_key,
            'nonce': self.__nonce_v,
            'signature': self.__signature(),
        }

    def __signature(self) -> str:
        st = "%s%s" % (self.__nonce_v, self._api_key)
        signature_hash = hmac.new(bytes(self._api_secret, 'latin-1'), bytes(st, 'latin-1'),
                                  hashlib.sha256).hexdigest()
        return signature_hash.upper()

    def __nonce(self):
        time_now = datetime.now()
        self.__nonce_v = round((time.mktime(time_now.timetuple()) + time_now.microsecond / 1000000.0) * 100)
        self._debug_message("Nonce: {}".format(self.__nonce_v))
