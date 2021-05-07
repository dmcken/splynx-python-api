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

~~~python
from splynx_api.v2 import CustomerRequest, AdministratorRequest, ApiKeyRequest
~~~

For create API clint instance need set into constructor `Splynx url`, `login` and `password`
if you want auth as customer or admin and api key and api secret for use api key for auth.

~~~python
customer = CustomerRequest('http://splynx.domain.com', 'login', 'password')
admin = AdministratorRequest('http://splynx.domain.com', 'admin', 'password')
key = ApiKeyRequest('http://splynx.domain.com', 'key', 'sec')
~~~

For login need get tokens which will be used on API requests.
~~~python
if customer.login():
    exit("Error while login")

# here can make api requests
~~~

For make API requests to Splynx you can use following methods:
+ 