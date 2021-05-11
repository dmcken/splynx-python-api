import pickle

from splynx_api.v2 import ApiKeyRequest as SplynxApi

AUTH_FILE = 'auth.pkl'

auth_data = None


def read_auth_data():
    with open(AUTH_FILE, 'rb') as file:
        return pickle.load(file)


def save_auth_data(_auth_data):
    with open(AUTH_FILE, 'wb') as file:
        pickle.dump(_auth_data, file)


api = SplynxApi('https://splynx.url/', 'apikey', 'secret', auth_data=read_auth_data())

if not api.renew_tokens():
    if not api.login():
        print("Error while login")
        exit(1)

api.api_call_get('admin/customers/customer')
print(api.response)

save_auth_data(api.auth_data)
