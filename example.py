#!/usr/bin/env python
# -*- coding: utf-8 -*-
import splynx_api
import json
# set API variables

api_url = 'http://SplynxURL/' # please set your Splynx URL
key = "SplynxKey" # please set your key
secret = "SplynxSecret" # please set your secret

ApiUrlCust = "admin/customers/customer" #API customers URL

api = splynx_api.SplynxApi(api_url, key, secret) 

api.api_call_get(ApiUrlCust)
customers = api.response
print json.dumps(customers)
