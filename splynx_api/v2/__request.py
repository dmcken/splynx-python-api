'''Splynx v2 API classes
'''


# System imports
import datetime
import hashlib
import hmac
import http.client
import logging
import time

from abc import ABC, abstractmethod
from urllib.parse import urlencode


# External imports
import requests

# Local imports
from .__exceptions import ApiCallError


logger = logging.getLogger(__name__)

AUTH_TYPE_API_KEY = 'api_key'
AUTH_TYPE_CUSTOMER = 'customer'
AUTH_TYPE_SESSION = 'session'
AUTH_TYPE_ADMIN = 'admin'


class BaseRequest(ABC):
    """
    Base class for implement external interface for all API auth types requests.
    """

    TOKEN_URL = 'admin/auth/tokens'

    def __init__(self, splynx_domain: str, debug: bool = False,
                 auth_data: dict = None, timeout:int = 600):
        """
        Init method for Splynx API class
        :param str splynx_domain: Splynx API domain. Example: https://splynx.domain.com
        :param bool debug: flag for enable debug message.
        :param dict auth_data: saved tokens for auth.
        """
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
        self.auth_data = auth_data

        self.__timeout = timeout

    def make_request(self, method: str, path: str, params: dict = None,
                     content_type: str = 'application/json',
                     skip_login: bool = False, entity_id=None):
        """
        Method for make different http requests types.

        Method automatically login on system or you can do it manually.
        For manually usage you can use method login or set auth tokens from local storage.

        :param str method: HTTP request methods names. Available methods: get,
            post, put, delete, option, head.
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
            raise ApiCallError(
                f"Error while make API call. Error: {exception}"
            ) from exception

        self.__process_response(response)

        return self.__result

    def __create_url(self, path: str, entity_id=None) -> str:
        request_url = self._splynx_domain + '/api/2.0/' + path.lstrip('/')

        if entity_id is not None:
            request_url = request_url.rstrip('/') + "/" + str(entity_id)

        return request_url

    def __do_requests(self, request_url: str, method: str, headers: dict, params: dict = None):
        self._debug_message(f"{method}: {request_url}")
        self._debug_message(f"Params: {params}")

        self.renew_tokens()

        if method == 'post' or method == 'put':
            return requests.request(
                method,
                request_url,
                headers=headers,
                json=params,
                timeout=self.__timeout,
            )
        else:
            if params:
                request_url = request_url + "?" + urlencode(params)

            return requests.request(
                method,
                request_url,
                headers=headers,
                timeout=self.__timeout,
            )

    def __process_response(self, response: requests.Response):
        '''Process the response from the API.
        '''
        self._debug_message(f"Response test: {response.text}")
        self._debug_message(f"Response code: {response.status_code}")
        if not response.text:
            self.__response = {}
        else:
            self.__response = response.json()

        self.__result = self.__get_result_by_status_code(response)

    @staticmethod
    def __get_result_by_status_code(response: requests.Response) -> bool:
        '''Determine the result value from status code.
        '''
        if response.request.method in ['GET','OPTION'] and \
            response.status_code == 200:
            return True

        if response.request.method in ['DELETE','HEAD'] and \
            response.status_code == 204:
            return True

        if response.request.method == 'POST' and response.status_code == 201:
            return True

        if response.request.method == 'PUT' and response.status_code == 202:
            return True

        return False

    def __get_request_header(self, content_type: str = 'application/json',
                             skip_login: bool = False) -> dict:
        '''Get the request header.
        '''
        return {
            'authorization': self.__get_auth_header(skip_login),
            'content-type': content_type,
            'user-agent': 'Splynx Python API v2'
        }

    def __get_auth_header(self, skip_login: bool = False) -> str:
        '''Get the authentication header'''
        if skip_login is False and self.__access_token is None:
            self.login()

        return "Splynx-EA (access_token=" + str(self.__access_token) + ")"

    def renew_tokens(self):
        '''Renew an expiered token'''
        if self.__refresh_token_expiration is None or self.__access_token_expiration is None:
            return False

        if self.__refresh_token_expiration > time.time() + 5 > self.__access_token_expiration:
            result = self.make_request(
                "GET",
                self.TOKEN_URL,
                entity_id=self.__refresh_token,
                skip_login=True
            )
            if result:
                return False
            self.auth_data = self.__response

        return True

    def login(self):
        """
        Method for authorize on Splynx system API.

        This method make api call to Splynx system and generate API tokens.
        After you can save token into your storage an use in future, but these
        tokens have an expiration time.
        See more details about Splynx API authorization on
        page: https://splynx.docs.apiary.io/#introduction/authentication/by-access-token

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
        '''Fetch authentication data.
        '''
        return {
            'access_token': self.__access_token,
            'access_token_expiration': self.__access_token_expiration,
            'refresh_token': self.__refresh_token,
            'refresh_token_expiration': self.__refresh_token_expiration,
            'permissions': self.__permissions,
        }

    @auth_data.setter
    def auth_data(self, data: dict):
        '''Set authentication data.
        '''
        if data is None:
            return

        self.__access_token = data.get('access_token')
        self.__access_token_expiration = data.get('access_token_expiration')
        self.__refresh_token = data.get('refresh_token')
        self.__refresh_token_expiration = data.get('refresh_token_expiration')
        self.__permissions = data.get('permissions')

    @property
    def result(self):
        '''Fetch result'''
        return self.__result

    @property
    def response(self):
        '''Fetch raw response?'''
        return self.__response

    @property
    def debug(self):
        '''Internal debugging'''
        return self._debug

    @debug.setter
    def debug(self, value: bool):
        '''Internal debugging'''
        self._debug = value

    def enable_http_debug(self) -> None:
        '''Enable HTTP debugging'''
        http.client.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def disable_debug(self) -> None:
        '''Disable HTTP debugging'''
        http.client.HTTPConnection.debuglevel = 0
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.WARNING)
        requests_log.propagate = False

    def _debug_message(self, message: str = ""):
        """
        Print debug message if debug enabled
        :param message:
        :return:
        """
        if self.debug:
            print(message)

    def api_call_get(self, path: str, entity_id=None, params: dict = None):
        """
        Method for make GET requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :param int|str|None entity_id:
        :param dict params: search conditions
        :return:
        """
        return self.make_request('get', path, params=params, entity_id=entity_id)

    def api_call_delete(self, path: str, entity_id=None, params: dict = None):
        """
        Method for make DELETE requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :param int|str|None entity_id:
        :param dict params: search conditions
        :return:
        """
        return self.make_request('delete', path, entity_id=entity_id, params=params)

    def api_call_post(self, path: str, params: dict = None):
        """
        Method for make POST requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :param dict params:
        :return:
        """
        return self.make_request('post', path, params)

    def api_call_put(self, path: str, entity_id, params: dict):
        """
        Method for make PUT requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :param int|str entity_id:
        :param dict params:
        :return:
        """
        return self.make_request('put', path, entity_id=entity_id, params=params)

    def api_call_options(self, path: str):
        """
        Method for make OPTIONS requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :return:
        """
        return self.make_request('options', path)

    def api_call_head(self, path: str, params: dict = None):
        """
        Method for make HEAD requests to Splynx API
        :param str path: Splynx API path. See more details: https://splynx.docs.apiary.io/
        :param dict params: search requests
        :return:
        """
        return self.make_request('head', path, params=params)


class PersonRequest(BaseRequest):
    """
    Base class for realize logic for auth as person on Splynx as admin or customer.
    """

    def __init__(self, splynx_domain: str, login: str = None,
                 password: str = None, debug: bool = False,
                 auth_data: dict = None):
        '''Constructor
        '''
        self._login = login
        self._password = password
        super().__init__(splynx_domain, debug=debug, auth_data=auth_data)

    def _auth_request_data(self) -> dict:
        return {
            'login': self._login,
            'password': self._password,
        }


class CustomerRequest(PersonRequest):
    """
    Splynx API helper with auth as customer.

    For authorize need use customer login and password.

    Usage:
        customer = CustomerRequest('http://splynx.domain.com', 'login', 'password')
    """

    def _auth_request_data(self) -> dict:
        auth_data = super()._auth_request_data()
        auth_data['auth_type'] = AUTH_TYPE_CUSTOMER
        return auth_data


class AdministratorRequest(PersonRequest):
    """
    Splynx API helper with auth as administrator.

    For authorize need use customer login and password.

    Usage:
        admin = AdministratorRequest('http://splynx.domain.com', 'admin', 'password')
    """

    def _auth_request_data(self) -> dict:
        auth_data = super()._auth_request_data()
        auth_data['auth_type'] = AUTH_TYPE_ADMIN
        return auth_data


class ApiKeyRequest(BaseRequest):
    """
    Splynx API helper with auth with API key.

    Usage:
        key = ApiKeyRequest('http://splynx.domain.com', 'key', 'sec')
    """

    def __init__(self, splynx_domain: str, api_key: str = None,
                 api_secret: str = None, debug: bool = False,
                 auth_data: dict = None):
        '''Constructor
        '''
        super().__init__(splynx_domain, debug=debug, auth_data=auth_data)
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
        '''Full signature creation.
        '''
        signature_str = f"{self.__nonce_v}{self._api_key}"
        signature_hash = hmac.new(
            bytes(self._api_secret, 'latin-1'),
            bytes(signature_str, 'latin-1'),
            hashlib.sha256
        ).hexdigest()
        return signature_hash.upper()

    def __nonce(self) -> None:
        '''Generate and save to the object the nonce value.
        '''
        time_now = datetime.datetime.now()
        self.__nonce_v = round(
            (time.mktime(time_now.timetuple()) + time_now.microsecond / 1000000.0) * 100
        )
        self._debug_message(f"Nonce: {self.__nonce_v}")
