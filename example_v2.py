from splynx_api.v2 import AdministratorRequest as SplynxApi

api = SplynxApi('https://mishchanchuk.dev.spl.splynx.rv.ua/', 'admin', 'q1w2e3')
print(api.login())
print(api.auth_data)
api.make_request('GET', 'admin/customers/customer')
print(api.response)
print(api.logout())
