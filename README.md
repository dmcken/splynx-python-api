# Splynx Python API

## Installation

For install you can use pip or git.

#### Git installation

Clone repo:

~~~
git clone https://bitbucket.org/splynx/splynx-python-api.git
~~~

Go to repository directory:

~~~
cd splynx-python-api
~~~

Run installation:

~~~
python3 setup.py install
~~~

#### Pip installation

Run following command for install using pip:

~~~
pip3 install -e git+https://bitbucket.org/splynx/splynx-python-api.git@master#egg=splynx_api
~~~

## Usage guide

For use Splynx API in python need import splynx_api package.

~~~
from splynx_api.v2 import CustomerRequest, AdministratorRequest, ApiKeyRequest
~~~

For create API clint instance need set into constructor `Splynx url`, `login` and `password`
if you want auth as customer or admin and api key and api secret for use api key for auth.

~~~
customer = CustomerRequest('http://splynx.domain.com', 'login', 'password')
admin = AdministratorRequest('http://splynx.domain.com', 'admin', 'password')
key = ApiKeyRequest('http://splynx.domain.com', 'key', 'sec')
~~~

For login need get tokens which will be used on API requests.

~~~
if customer.login():
    exit("Error while login")

# here can make api requests
~~~

For make API requests to Splynx you can use following methods:

+ `api_call_get(path, entity_id, params)` - method for make GET requests to Splynx API. This method has the following arguments:
  `path` is Splynx API endpoint,
  `entity_id` id of record for load one record from API,
  `params` search [params](https://splynx.docs.apiary.io/#introduction/search,-order,-limit,-and-offset) for make search
  request to API. Usage:
  ~~~
  from splynx_api.v2 import ApiKeyRequest
  
  key = ApiKeyRequest("http://splynx.domain.com", "key", "sec")
  if key.login():
    exit("Error while login")
  
  key.api_call_get("admin/customers/customer")
  print(key.response)
  key.logout()
  ~~~

+ `api_call_post(path, params)` - method for make POST requests to Splynx API endpoint. This method has the following arguments:
  `path` is Splynx API endpoint, `params` params for entity creating, for example
  [list of customers attributes](https://splynx.docs.apiary.io/#reference/customers/customers-collection/create-a-customer). Usage:
  ~~~
  from splynx_api.v2 import ApiKeyRequest
  
  key = ApiKeyRequest("http://splynx.domain.com", "key", "sec")
  if key.login():
    exit("Error while login")
  
  key.api_call_post("admin/customers/customer", {
      'login': 'test',
      'name': 'Test User'
  })
  print(key.result)
  key.logout()
  ~~~
+ `api_call_put(path, entity_id, params)` - method for make PUT requests to Splynx API. This method has the following arguments:
  `path` is Splynx API endpoint,
  `params` fields to update on entity with the id in `entity_id` argument. Usage:
  ~~~
  from splynx_api.v2 import ApiKeyRequest
  
  key = ApiKeyRequest("http://splynx.domain.com", "key", "sec")
  if key.login():
    exit("Error while login")
  
  key.api_call_put("admin/customers/customer", 1, {
      'name': 'Test User'
  })
  print(key.result)
  key.logout()
  ~~~

+ `api_call_delete(path, entity_id)` - method for make DELETE requests to Splynx API. This method has the following arguments:
  `path` is Splynx API endpoint, `entity_id` is id of record for delete. Usage:
  ~~~
  from splynx_api.v2 import ApiKeyRequest
  
  key = ApiKeyRequest("http://splynx.domain.com", "key", "sec")
  if key.login():
    exit("Error while login")
  
  key.api_call_delete("admin/customers/customer", 1)
  print(key.result)
  key.logout()
  ~~~
  
+ `api_call_options(path)` - method for make OPTIONS requests to Splynx API.
  Method load endpoint `path` attributes list.
  
+ `api_call_head(path, params)` - method for make HEAD requests to Splynx API.
  Method for load records count on endpoint `path` by [search query](https://splynx.docs.apiary.io/#introduction/search,-order,-limit,-and-offset) on `params`.
