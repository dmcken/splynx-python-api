#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json

import splynx_api

# set API variables
api_url = 'https://splynx.url/'  # please set your Splynx URL
key = "apikey"  # please set your key
secret = "apisecret"  # please set your secret

ApiUrlCust = "admin/customers/customer"  # API customers URL

api = splynx_api.SplynxApi(api_url, key, secret)

api.api_call_get(ApiUrlCust)
customers = api.response
print(json.dumps(customers))
