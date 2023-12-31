# -*- coding: utf-8 -*-
import hashlib
import hmac
import sys
import time
from datetime import datetime

import deprecation
import requests
import urllib3
from requests import request


@deprecation.deprecated(deprecated_in='2.0', details="Please use v2 package")
class SplynxApi:
    """
       *Splynx API v. 1.0
       *REST API Class
       *Author: Narcisse Doudieu Siewe
     """

    def __init__(self, url, api_key, api_secret):
        self._url = url
        self._api_key = api_key
        self._api_secret = api_secret
        self._sash = None
        self._nonce_v = None
        self._debug = None
        self._version = '1.0'
        self._administrator_id = None
        self._administrator_role = None
        self._administrator_partner = None
        self._test_method = {'POST': 201, 'PUT': 202, 'DELETE': 204}
        self._nonce()

    @property
    def administrator_id(self):
        return self._administrator_id

    @administrator_id.setter
    def administrator_id(self, value):
        self._administrator_id = value

    @property
    def administrator_role(self):
        return self._administrator_role

    @administrator_role.setter
    def administrator_role(self, value):
        self._administrator_role = value

    @property
    def administrator_partner(self):
        return self._administrator_partner

    @administrator_partner.setter
    def administrator_partner(self, value):
        self._administrator_partner = value

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value):
        self._debug = value

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, value):
        self._response = value

    @property
    def response_code(self):
        return self._response_code

    @response_code.setter
    def response_code(self, value):
        self._response_code = value

    @property
    def sash(self):
        return self._sash

    @sash.setter
    def sash(self, value):
        self._sash = value

    def _signature(self):
        """
           *Create signature for API call validation
           *@return string hash
        """
        if sys.version_info >= (3, 0):
            st = "%s%s" % (self._nonce_v, self._api_key)
            hsh = hmac.new(bytes(self._api_secret, 'latin-1'), bytes(st, 'latin-1'), hashlib.sha256).hexdigest()
        else:
            st = "%s%s" % (self._nonce_v, self._api_key)
            hsh = hmac.new(self._api_secret, st, hashlib.sha256).hexdigest()
        return hsh.upper()

    def _nonce(self):
        """
           *Set nonce as timestamp
        """
        t_now = datetime.now()
        self._nonce_v = round((time.mktime(t_now.timetuple()) + t_now.microsecond / 1000000.0) * 100)
        if self.debug:
            print("nonce", self._nonce_v)

    def _request_process(self, method, url, param=[]):
        """
           *Send request request to Splynx API
           *@param method: get, delete, put, post
           *@param url
           *@param param
           *@return array JSON results
        """
        if self.debug:
            print("%s to %s\n" % (method, url))
            print(param, "\n")
        auth_str = self._make_auth()
        print(auth_str)
        headers = {
            "Authorization": "Splynx-EA (" + auth_str + ")",
            "user-agent": "Splynx Python API" + self._version
        }
        try:
            if method in ('POST', 'PUT'):
                rs = request(method, url, headers=headers, json=param)
            else:
                rs = request(method, url, headers=headers)
        except requests.RequestException as e:
            if self.debug:
                print("response: ", e.response, '\n')
                print("request: ", e.request, '\n')
                return
        self.administrator_id = rs.headers.get('SpL-Administrator-Id') or self.administrator_id
        self.administrator_role = rs.headers.get('SpL-Administrator-Role') or self.administrator_role
        self._administrator_partner = rs.headers.get('SpL-Administrator-Partner') or self._administrator_partner
        self.response_code = rs.status_code
        if self.debug:
            print('Content: ', rs.content, '\n')
        self.result = False
        if self.response_code == 200 or self._test_method.get(method) == self.response_code:
            self.result = True
        self.response = rs.json()
        if self.debug:
            print("status code: %s  method: %s\n" % (self.response_code, method))
        return self.response

    def _make_auth(self):
        """
           *Make Splynx Extended Authorization string
           *
           *@return string of Splynx EA
        """
        self._nonce_v += 1
        auth = {'key': self._api_key,
                'signature': self._signature(),
                'nonce': self._nonce_v}
        if self.sash != None:
            auth['sash'] = self.sash
        return urllib3.request.urlencode(auth)

    def _getUrl(self, pth, Id=None):
        url = self._url + 'api/' + self._version + '/' + pth
        if Id:
            url += '/' + str(Id)
        return url

    def api_call_get(self, path, Id=None):
        """
           *Send API call GET to Splynx API
           *@param string path
           *@param integer Id
           *@param a list
        """
        return self._request_process('GET', self._getUrl(path, Id))

    def api_call_delete(self, path, Id=None):
        """
           *Send API call DELETE to Splynx API
           *@param string path
           *@param integer Id
           *@return a list
        """
        return self._request_process('DELETE', self._getUrl(path, Id))

    def api_call_post(self, path, param):
        """
           *Send API call POST to Splynx API
           *@param string path
           *@param list param
           *@return a list
        """
        return self._request_process('POST', self._getUrl(path), param)

    def api_call_put(self, path, Id, param):
        """
           *Send API call PUT to Splynx API
           *@param string path
           *@param integer Id
           *@param list param
           *@return a list
        """
        return self._request_process('PUT', self._getUrl(path, Id), param)
