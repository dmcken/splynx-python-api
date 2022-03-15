from .__request import CustomerRequest, AdministratorRequest, ApiKeyRequest

"""
Module for working with Splynx API v2.0.

Module contains:
    CustomerRequest - class for make API requests using auth as customer.
    AdministratorRequest - class for make API requests using auth as administrator.
    ApiKeyRequest - class for make API requests with API key for auth.
"""

__all__ = ["CustomerRequest", "AdministratorRequest", "ApiKeyRequest"]
