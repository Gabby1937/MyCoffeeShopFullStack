import json
from flask import abort, request
from functools import wraps
from urllib.request import urlopen
from jose import jwt
#import jwt
import sys



AUTH0_DOMAIN = 'gabby.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'sipp'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    
    # Obtains the Access Token from the Authorization Header
    auth = request.headers.get('Authorization', None)

    # Check if the auth header is available
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    # Check if it bearer or not
    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    # Check if the Token is available
    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    # Check if the Token is bearer
    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)
        
    elif parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'Invalid Header',
            'description': 'Authorization Header Must start with "Bearer". '
        }, 401)

    token = parts[1]
    return token


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''

def check_permissions(permission, payload):
    if 'permissions' not in payload:
        print("Permissions not in payload")
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'permissions not included in JWT'
        }, 403)

    if permission not in payload['permissions']:
        print(f'The passed permission <{permission}> is not in the payload')
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission Not Found'
        }, 403)

    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:

            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.PyJWTError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
    }, 400)

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            jwt = get_token_auth_header()
            #try:
            payload = verify_decode_jwt(jwt)
            check_permissions(permission, payload)
            # except Exception:
            #     print('exception happened while -- Verify_decode_JWT')
            #     print(sys.exc_info())
            #     abort(401)
            
            #print(f'permission checked and the result is:  {res}')
            # return f(payload,*args, **kwargs)
            return f(*args, **kwargs)
        return wrapper

    return requires_auth_decorator


# def requires_auth(permission=''):
#     def requires_auth_decorator(f):
#         @wraps(f)
#         def wrapper(*args, **kwargs):
#             tok = get_token_auth_header()
#             payload = verify_decode_jwt(tok)
#             res = check_permissions(permission, payload)
#             print(f'Permission checked, result: {res}')
#             return f(payload, *args, **kwargs)

#         return wrapper

#     return requires_auth_decorator
