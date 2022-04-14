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
import json
import logging
import functools
from flask import g
from flask import abort
from flask import url_for
from flask import request
from flask import redirect
from flask import Response
from flask import after_this_request

from laikarest.error import AuthMethodNotInUse
from laikarest.error import AuthAttemptedButFailed
from laikarest.error import AuthenticationFailureError

def enforce_auth(*expected_args, **kwargs):
    if "laika_auth" not in kwargs:
        raise ValueError("laika_auth must be present to enforce authetication")
    laika_auth = kwargs["laika_auth"]
    def decorator_require_basic_auth(func):
        @functools.wraps(func)
        def wrapper_require_basic_auth(*args, **kwargs):
            user_agent = request.headers.get('User-Agent', 'not-provided').lower()
            valid_browsers = [
                "chrome",
                "firefox",
                "safari",
                "msie",
                "opera"
            ]

            using_browser = any([ browser in user_agent for browser in valid_browsers])
            try:
                if not laika_auth.session_already_exists(request):
                    success_username = None # variable to hold succesfully authenticated username
                    auth_successful = False # whether or not authentication succeeded
                    # Get cached ldap session
                    init_ldap_conn = laika_auth.get_initial_ldap_conn()                    
                    # -----------has the reverse proxy authenticated this user? -------
                    try:
                        success_username = laika_auth.check_for_remote_user(request)
                    except AuthAttemptedButFailed as e:
                        logging.info(e)
                    except AuthMethodNotInUse as e:
                        logging.debug(e)
                    except AuthenticationFailureError:
                        pass
                    
                    # ------------------ BASIC AUTH WITH LDAP ----------------
                    try:
                        # if already authenticated then don't check for basic auth
                        if not success_username:
                            success_username = laika_auth.check_for_basic_auth(request)
                    except Exception as e:
                        logging.debug(e)

                    # Access logs
                    if success_username:
                        request.environ["REMOTE_USER"] = success_username
                    
                    # Make sure the user is in one of the specified groups, or list of 
                    # valid users if the user has been validated via previous auth method
                    auth_successful = success_username and \
                        laika_auth.check_user_authorization(init_ldap_conn, success_username)

                    # Certain routes are allowed to be accessed anonymously. Laikaboss
                    # will still try to auth users if they 
                    anonymous_route = laika_auth.anonymous_route(request)
                    if not auth_successful and not anonymous_route:
                        if using_browser:
                            # @after_this_request
                            # def set_session(response):
                            #     return redirect(url_for("login"), code=302)
                            raise Exception("Failed to authenticate.")
                        elif success_username:
                            raise Exception("Provided user is not in a required metagroup")
                        else:
                            raise Exception("Failed to authenticate.")
                    elif success_username:
                        logging.info("Auth success. Session will be issued for {}".format(success_username))
                        laika_auth.create_session(success_username)

            except Exception as e:
                logging.exception('Error while authenticating user')
                abort(Response(json.dumps({"errmsg": str(e)}), 401, {'WWW-Authenticate': 'Basic'}))
            return func(*args, **kwargs)
        return wrapper_require_basic_auth
    return decorator_require_basic_auth
