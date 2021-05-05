from splynx_api.v2 import AdministratorRequest as SplynxApi

api = SplynxApi('https://mishchanchuk.dev.spl.splynx.rv.ua/', 'admin', 'q1w2e3', debug=True)
print(api.login())
api.make_request('GET', 'admin/customers/customer', {
    'id': 1
})
print(api.response)
api.logout()
