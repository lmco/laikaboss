# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from builtins import object
import re
import os
import sys
import time
import ldap
import json
import redis
import bcrypt
import base64
import logging
import binascii
from jose import jwt
from flask import after_this_request
from passlib.apache import HtpasswdFile

from laikarest.error import AuthMethodNotInUse
from laikarest.error import AuthAttemptedButFailed
from laikarest.error import AuthenticationFailureError

class LaikaRestAuth(object):
    def __init__(self, ldap_config, auth_config, jwt_settings, redis_client, ca_cert=None):
        """
        Handle, authentication and session management.

        Args:
            ldap_config (dict): Containing all ldap_ prefixed
                configuration settings. Sample options include:
                    ldap_uri
                    ldap_base
                    ldap_account_base
                    ldap_group_base
                    ldap_auth_dn
                    ldap_auth_dn_pw
                    ldap_valid_groups
                    (optional) ldap_ca_cert
            auth_config (dict): All other auth settings. Auth
                settings are specfied via an auth_ prefix.
            jwt_settings (dict): All settings related to signing
                jwt tokens.
            redis_client (redis.Redis): redis connection
            ca_cert (str): A path to the optional CA certificate
                required for LDAP TLS

        """
        self.ldap_config = ldap_config
        self.auth_config = auth_config
        self.jwt_settings = jwt_settings
        self.redis_client = redis_client
        self.ca_cert = ca_cert
        self.password_cache_max_age_secs = int(auth_config["auth_password_cache_max_age_secs"])
        self.ldap_conn = False
        self.ldap_conn_age = 0
        # Default: 1/2 hour
        self.ldap_refresh_interval = int(ldap_config.get("ldap_refresh_interval", "1800"))

        password_file = auth_config.get('auth_user_password_db')

        if not password_file:
             raise ValueError("missing value for auth_user_password_db")

        self.htpasswd = HtpasswdFile(password_file)

    def _get_ldap_connection(self):
        """Creates an ldap configuration for use in LDAP queries"""
        timeout = 5
        try:
            timeout = int(self.ldap_config.get("ldap_timeout_secs", "5"))
        except ValueError:
            logging.error("ldap_timeout is not a valid str representation of an int")
            timeout = 5

        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)

        ldap_uri = self.ldap_config["ldap_uri"].lower().strip()

        conn = ldap.initialize(ldap_uri)
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        if isinstance(self.ca_cert, str) and len(self.ca_cert) != 0:
            # Ensure the certificate is trusted
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            # Set location to a cert file
            conn.set_option(ldap.OPT_X_TLS_CERTFILE, self.ca_cert)
            # Require TLS connection
            conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
        conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        return conn

    def _check_valid_users(self, username):
        """ Check if this user can bypass being in a valid ldap group 
        
        Args:
            username (str): The user that has already been authenticated
        
        Returns:
            validated (bool) True if authorized, False otherwise
        """
        auth_valid_users = []
        if not hasattr(self, "auth_valid_users"):
            if "auth_valid_users" in self.auth_config:
                try:
                    auth_valid_users = json.loads(self.auth_config["auth_valid_users"])
                    if not isinstance(auth_valid_users, list):
                        raise Exception ("auth_valid_users config item must be a list")
                    self.auth_valid_users = auth_valid_users
                except Exception as e:
                    logging.error(e)
                    return False

        return username in self.auth_valid_users

    def session_already_exists(self, request):
        """ Checks if the provided user already has a session
        Args: 
            request(flask.request): the http request details
        Returns:
            (bool): True if the session exists, false otherwise
        """
        username =  None
        try:
            username = self.check_for_token(request)
        except AuthMethodNotInUse:
            # JWT token not found
            pass
        except AuthAttemptedButFailed:
            # Attempted to use JWT token, but failed to verify session
            pass
        except Exception as e:
            logging.exception(e)

        try:
            username = username or self.check_for_cookie(request)
            if username:
                request.environ["REMOTE_USER"] = username
        except AuthMethodNotInUse:
            logging.debug("No preexisting session was provided")
            return False
        except AuthAttemptedButFailed:
            logging.debug("Cookie was provided, but did not validate")
            return False
        except Exception as e:
            logging.exception(e)
            return False
        return True

    def _generate_session_id(self):
        """ Create a cryptographically secure random number """
        sec = binascii.hexlify(os.urandom(32))
        return str(sec.decode('ascii'))

    def _allowed_remote_route(self, request):
        """ Checks if this route is allowed to trust a special auth header

        Args:
            request (flask.request): the http request

        Returns:
            (bool): True if route is allowed to use deferred auth, false
                otherwise
        """
        special_routes = []
        try:
            special_routes = json.loads(self.auth_config["auth_trust_header_in_urls"])
        except:
            return False

        return str(request.url_rule) in special_routes

    def create_session(self, username):
        """ Creates a token based session for the specified user 
        Args:
            username(str): The user that we want to create a session for
        Raises: 
            (AuthenticationFailureError): If the session cannot be created
        """
        max_cookie_age = 60 * 60 * 3 # default 3 hours
        if "auth_cookie_max_age" in self.auth_config:
            try:
                max_cookie_age = int(self.auth_config.get("auth_cookie_max_age", max_cookie_age))
            except ValueError:
                logging.error("auth_cookie_max_age is not a valid str reprsentation of int")

        session_id = self._generate_session_id()
        redis_key = "session:{}".format(session_id)
        try:
            logging.debug('redis session: %s' % (redis_key))
            self.redis_client.set(redis_key, username, ex=max_cookie_age)
        except redis.RedisError as e:
            logging.exception(e)
            # raise AuthenticationFailureError("Failed to create session!")

        @after_this_request
        def set_session(response):
            response.set_cookie('session_id', session_id, max_age=max_cookie_age)
            return response

    def anonymous_route(self, request):
        """ Checks if a route can be used without authentication 
        Args:
            request (flask.request): The request containing the route
        Returns:
            (bool): True if anonymous, False
        """
        route = request.url_rule
        if not hasattr(self, "anon_routes"):
            if "auth_allowed_anonymous_routes" not in self.auth_config:
                return False
            try:
                self.anon_routes = json.loads(self.auth_config["auth_allowed_anonymous_routes"])
            except:
                logging.error("invalid configuration item 'auth_allowed_anonymous_routes'")
                self.anon_routes = []
        
        route_is_anon = str(route) in self.anon_routes
        return route_is_anon


    def check_for_remote_user(self, request):
        """ Checks if a user has been authenticated by a reverse proxy.

        Args:
            request (flask.request): The http request

        Raises: 
            AuthMethodNotInUse: if this auth method is not being used
            AuthAttemptedButFailed: if this auth method was attempted
                but failed
            AuthenticationFailureError: generic failure

        Returns:
            username (str): The username of the authenticated user
        """
        if "auth_trusted_header" not in self.auth_config:
            raise AuthMethodNotInUse("Reverse proxy auth not allowed in config")

        if "auth_trust_header_in_urls" not in self.auth_config:
            raise AuthMethodNotInUse("There are no headers allowing a trusted header")

        if not self._allowed_remote_route(request):
            raise AuthMethodNotInUse("Route is not allowed to use a trusted header")

        remote_user = request.environ.get(self.auth_config["auth_trusted_header"], None)
        if not remote_user:
            raise AuthMethodNotInUse
        if isinstance(remote_user, bytes):
            remote_user = remote_user.decode('utf-8')

        request.environ["REMOTE_USER"] = remote_user
        return remote_user

    def _get_redis_cache(self, key):
        """ A wrapper for getting a key in redis, except errors are consumed.
        """
        try:
            return self.redis_client.get(key)
        except Exception as e:
            logging.exception(e)
        return None

    def _put_redis_cache(self, key, val):
        """
            Set the desired redis key and value. Consume errors.

        Returns:
            (bool): for success or failure
        """
        try:
            self.redis_client.set(key, val, ex=self.password_cache_max_age_secs)
            return True
        except Exception as e:
            logging.exception(e)

        return False

    def check_local_identity(self, user, password):

        self.htpasswd.load_if_changed()
        return self.htpasswd.check_password(user, password)

    def check_identity(self, conn, bind_dn, password):
        """ LDAP identity check using the provided credentials
        Args:
            conn (ldap): the details of the LDAP endpoint
            bind_dn (str): the resource to auth with 
            password (str): the password of the user
        Throws:
            AuthenticationFailureError if the authentication did not succeed
            AuthAttemptedButFailed: if this auth method was attempted
                but failed
            AuthenticationFailureError: generic failure
            Exception: Something else went wrong
        """

        # grab any prexisting salt for the bind_dn provided
        salt = self._get_redis_cache(bind_dn)
        if salt == None:
            logging.debug("salt for {} not found in redis".format(bind_dn))
            # No salt found, create a new salt
            salt = bcrypt.gensalt()
            self._put_redis_cache(bind_dn, salt)
        else:
            logging.debug("salt found for {}".format(bind_dn))


        # Hash password with provided salt
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Use the following key while looking up or storing
        # entries in the password cache
        cache_key = b'^'.join([bind_dn.encode('utf-8'), hashed_pw])

        # check if the result is in the cache
        cache_lookup = self._get_redis_cache(cache_key)
        if cache_lookup != None:
            logging.debug("Found entry in the password cache")
            if cache_lookup == 'false':
                logging.debug("Password cache labeled auth request as unsuccessful")
                raise AuthAttemptedButFailed("Authentication Failure")
            elif cache_lookup == 'true':
                logging.debug("Password cache labeled auth request as successful")
                return True # Success!

        try:
            try:
                result = conn.simple_bind_s("%s" % (bind_dn), password)
                # if execution made it this far, then authentication via ldap was successful
                self._put_redis_cache(cache_key, 'true')
            except ldap.INVALID_CREDENTIALS as e:
                logging.exception(e)
                raise AuthAttemptedButFailed("Authentication failed")
            except ldap.NO_SUCH_OBJECT as e:
                logging.exception(e)
                raise AuthAttemptedButFailed("Authentication failed")
            except ldap.LDAPError as e:
                logging.exception(e)
                raise AuthAttemptedButFailed("Authentication failed")
            except Exception as e:
                logging.exception(e)
                raise AuthenticationFailureError("Something unexpected happened")
        except:
            # Authentication via ldap was unsuccessful
            self._put_redis_cache(cache_key, 'false')
            raise


    def get_initial_ldap_conn(self):
        """ Create or a global LDAP connection used for groups.
            If The connection gets too old, refresh it.
        """
        ldap_auth_dn = self.ldap_config["ldap_auth_dn"]
        ldap_auth_dn_pw = self.ldap_config["ldap_auth_dn_pw"]
        if not self.ldap_conn or self.ldap_conn_age + self.ldap_refresh_interval < time.time():
            logging.info("Initiating connection to LDAP")
            conn = self._get_ldap_connection()
            self.check_identity(conn, ldap_auth_dn, ldap_auth_dn_pw)
            self.ldap_conn = conn
            self.ldap_conn_age = time.time()
            logging.info("LDAP connection available")
        return self.ldap_conn

    def extract_basic_auth_creds(self, auth_string):
        """ Extract credentials from a basic auth string
        Args:
            auth_string(str): a string of the format basic base64

        Raises:
            (AuthenticationFailureError): When failing to extract
                credentials as basic auth.

        Returns:
            (tuple): username, password
        """
        auth_parts = auth_string.split()
        if len(auth_parts) is not 2:
            raise AuthenticationFailureError("Invalid basic auth format")
        basic_auth_encoded = auth_parts[-1]
        decoded_creds = base64.b64decode(basic_auth_encoded).decode('utf-8')
        if ":" not in decoded_creds:
            raise AuthenticationFailureError("Invalid basic auth format")
        creds = decoded_creds.split(":")
        if len(creds) is not 2:
            raise AuthenticationFailureError("Invalid basic auth format")

        return creds[0], creds[1]

    def check_user_authorization(self, conn, username):
        """ LDAP authorization check. Is the user in a valid ldap group?

        Args:
            conn (ldap): the details of the LDAP endpoint
            username (str): the username of the user

        Throws:
            (AuthenticationFailureError) if the user was not found to
                be in a valid ldap group.

        Returns:
            True if the user was in a required group
        """
        # Certain users are allowed to bypass being in a valid LDAP group
        if self._check_valid_users(username):
            logging.debug("User: {} was allowed to bypass ldap groups".format(username))
            return True
        # load site ldap info
        ldap_account_base = self.ldap_config["ldap_account_base"]
        group_attribute = self.ldap_config["ldap_group_attribute"]
        ldap_account_prefix = self.ldap_config["ldap_account_prefix"]
        group_prefix = self.ldap_config["ldap_group_prefix"]

        search_filter="{}={}".format(ldap_account_prefix, username)
        try:
           results = conn.search_s(ldap_account_base, ldap.SCOPE_SUBTREE, search_filter, [ group_attribute ])
        except ldap.FILTER_ERROR as e:
           raise AuthenticationFailureError("ldap filter error, ldap_account_base:'{}', search_filter:'{}', group_attribute:'{}'".format(ldap_account_base, search_filter, group_attribute))

        if len(results) is not 1:
            raise AuthenticationFailureError("Failed to perform metagroup search")
        results = results[0]
        if not isinstance(results, tuple):
            raise AuthenticationFailureError("Failed to perform metagroup search")
        if results[0].lower() != "{},{}".format(search_filter, ldap_account_base.lower()):
            raise AuthenticationFailureError("Failed to perform metagroup search")
        if not isinstance(results[1], dict):
            raise AuthenticationFailureError("Failed to perform metagroup search")
        if group_attribute not in results[1]:
            raise AuthenticationFailureError("Failed to perform metagroup search")
        if not isinstance(results[1][group_attribute], list):
            raise AuthenticationFailureError("Failed to perform metagroup search")

        user_memberof_groups = results[1][group_attribute]
        # Lower case all the metagroups
        user_memberof_groups = [group.lower() for group in user_memberof_groups]

        regex = "(?:{}=(?P<prefix>[^,]+).*)".format(group_prefix).encode('utf-8')
        # Remove everything that isn't the actual group name
        user_memberof_groups = [ re.search(regex, lgroup).group("prefix").decode('utf-8') for lgroup in user_memberof_groups ]

        valid_groups = json.loads(self.ldap_config["ldap_valid_groups"])
        # Lower case all the valid metagroups
        valid_groups = [vgroup.lower() for vgroup in valid_groups]
        for valid_group in valid_groups:
            if valid_group in user_memberof_groups:
                logging.debug("user {} in group {}".format(username, valid_group))
                return True

        # The user was not found in any of the applications metagroups
        raise AuthenticationFailureError("User %s was not found to be in a valid ldap group nor on the trusted id list" % (username))

    def check_for_basic_auth(self, request):
        """ Confirms the identity of a user using basic auth and ldap

        Args:
            request (flask.Request): The request object from which
                to extract the credentials from

        Raises:
            AuthMethodNotInUse: if this auth method is not being used
            AuthAttemptedButFailed: if this auth method was attempted
                but failed
            AuthenticationFailureError: generic failure

        Returns:
            username (str): The user that has been authenticated
        """
        auth_string = request.environ.get("HTTP_AUTHORIZATION", "")
        using_basic_auth = auth_string.lower().startswith("basic")
        if not using_basic_auth:
            raise AuthMethodNotInUse("Not using basic auth")

        username, password = self.extract_basic_auth_creds(auth_string)
        if not username or not password or username == 'None' or username == 'None':
            logging.error("Tried to basic auth with username: {} but failed".format(username))
            raise AuthAttemptedButFailed("Null username and/or password")
        conn = self._get_ldap_connection()
        ldap_account_base = self.ldap_config["ldap_account_base"]
        authed_user_account_base = "%s=%s,%s" % (self.ldap_config["ldap_account_prefix"], username, ldap_account_base)

        if self.check_local_identity(username, password):
           return username

        try:
            self.check_identity(conn, authed_user_account_base, password)
        except AuthAttemptedButFailed as e:
            request.environ["REMOTE_USER"] = username # keep in access-logs even on failure
            raise AuthAttemptedButFailed("{} attempted basic auth but failed to verify with LDAP".format(username))

        return username

    def check_for_token(self, request):
        """ Check for a valid JWT token.

        Args:
            request (Flask.request): the http request details
        """
        access_token = ""
        try:
            if "access_token" in request.form:
                access_token = request.form["access_token"]

            if not access_token:
                access_token = request.headers.get("Authorization") or ""
                if "bearer " in access_token.lower():
                    access_token = access_token.split(" ")[1]
                if "basic" in access_token.lower():
                    raise AuthMethodNotInUse("No access_token found in the request")
        except Exception as e:
            raise AuthMethodNotInUse("No access_token found in the request")

        if not access_token:
            raise AuthMethodNotInUse("No access_token found in the request")

        if not self.token_auth(access_token, request):
            raise AuthAttemptedButFailed("Token failed to authenticate")

    def check_for_cookie(self, request):
        session_id = request.cookies.get('session_id')
        if not session_id:
            raise AuthMethodNotInUse("Cookie session not set")

        username = None

        try:
            username = self.redis_client.get("session:{}".format(session_id))
        except Exception as e:
            logging.exception(e)

        if username and isinstance(username, bytes):
            username = username.decode('utf-8')

        if not username:
            raise AuthAttemptedButFailed("Session is invalid")

        return username


    def sign_jwt(self, user, issuer):
        """ NOT in use at the moment"""
        settings = self.jwt_settings[issuer]
        issuer = settings['issuer']
        private_key_file = settings['keyfile.private']
        private_key = open(private_key_file, "r").read().strip()
        expires = time.time() + 60*60*10
        claim = settings['claim']
        audience = settings['audience']

        encoded = jwt.encode(
            {
                'nameid':user,
                'client':'laikaboss-gui',
                'iss':issuer,
                'exp':expires,
                'token_type': 'Bearer',
                'scope': [u'openid', u'email', u'profile', u'offline_access'],
                'claim': "True",
                'aud': audience
            },
            private_key,
            algorithm='RS256'
        )

        return encoded

    def token_auth(self, access_token, request):
        """ Verify a json web token """
        match = False
        scope = []

        try:
            unverified_token = jwt.get_unverified_claims(access_token)
        except Exception as e:
            raise

        token_issuer = unverified_token.get("iss")

        jwk_settings = self.jwt_settings[token_issuer]

        require_key = open(jwk_settings.get("keyfile.public"), "r").read().strip()
        require_audience = jwk_settings.get("audience")
        require_issuer = jwk_settings.get("issuer")
        require_scope = jwk_settings.get("scope")
        require_claim = jwk_settings.get("claim")

        claim_value = None

        try:
            result = jwt.decode(access_token, require_key, audience=require_audience, issuer=require_issuer, options={"leeway": 300})
            scope = result.get("scope", None)
            client = result.get("client", "UNKNOWN")
            nameid = result.get("nameid", "UNKNOWN")
            claim_value = result.get(require_claim, None)
        except Exception as e:
            raise

        success = False

        grant_type = "resource"
        remote_user = None

        if require_scope in scope:
            success = True
            grant_type = "client"
            remote_user = "client:" + client
        elif str(claim_value) == 'True':
            success = True
            remote_user = nameid

        if success:
            request.environ["LB_GRANT_TYPE"] = grant_type
            request.environ["REMOTE_USER"] = remote_user
            return True
        else:
            raise ValueError("Incorrect scope or claim")
