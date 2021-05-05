from splynx_api.v2 import ApiKeyRequest as SplynxApi

api = SplynxApi('https://splynx.url/', 'apikey',
                'apisicret', debug=True)
if not api.login():
    print("Error while login")
    exit(1)

api.make_request('GET', 'admin/customers/customer', {
    'id': 1
})
api.logout()
