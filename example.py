#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json

import splynx_api

# set API variables
api_url = 'https://mishchanchuk.dev.spl.splynx.rv.ua/'  # please set your Splynx URL
key = "0b20629c11a9408ea640cb0ba2fdd402"  # please set your key
secret = "485704f95505ee1f24f37d48156d3933"  # please set your secret

ApiUrlCust = "admin/customers/customer"  # API customers URL

api = splynx_api.SplynxApi(api_url, key, secret)

api.api_call_get(ApiUrlCust)
customers = api.response
print(json.dumps(customers))
