from splynx_api.v2 import ApiKeyRequest as SplynxApi

api = SplynxApi('https://splynx.url/', 'apikey', 'secret')
if not api.login():
    print("Error while login")
    exit(1)

api.api_call_get('admin/customers/customer')

print(api.response)

api.logout()
