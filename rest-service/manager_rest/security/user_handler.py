#########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from flask import current_app
from flask_security.utils import md5

from manager_rest.utils import abort_error
from manager_rest.storage import get_storage_manager
from manager_rest.manager_exceptions import (UnauthorizedError,
                                             NotFoundError,
                                             ConflictError)

from .security_models import user_datastore


def add_user_to_tenant(username, tenant_name):
    user = user_datastore.get_user(username)
    if not user:
        raise NotFoundError(
            'Requested username `{0}` not found'.format(username)
        )
    tenant = get_storage_manager().get_tenant_by_name(tenant_name)
    if not tenant:
        raise NotFoundError(
            'Requested tenant `{0}` not found'.format(tenant_name)
        )
    if tenant in user.tenants:
        raise ConflictError(
            'User `{}` is already associated to tenant `{}`'.format(
                username, tenant_name
            )
        )
    user.tenants.append(tenant)
    user_datastore.put(user)
    user_datastore.commit()
    return user


def unauthorized_user_handler(extra_info=None):
    error = 'User unauthorized'
    if extra_info:
        error += ': {0}'.format(extra_info)
    abort_error(
        UnauthorizedError(error),
        current_app.logger,
        hide_server_message=True
    )


def user_loader(request):
    """Attempt to retrieve the current user from the request
    Either from request's Authorization attribute, or from the token header

    Having this function makes sure that this will work:
    > from flask_security import current_user
    > current_user
    <manager_rest.security.security_models.User object at 0x50d9d10>

    :param request: flask's request
    :return: A user object, or None if not found
    """
    user, _ = get_user_and_hashed_pass(request)
    return user


def _get_user_from_token(token):
    """Return a tuple with a user object (or None) and its hashed pass
    using an authentication token

    :param token: A token generated from a user object
    """
    # Retrieve the default serializer used by flask_security
    serializer = current_app.extensions['security'].remember_token_serializer
    try:
        # The serializer can through exceptions if the token is incorrect,
        # and we want to handle it gracefully
        result = serializer.loads(token)
    except Exception:
        result = None

    # The result should be a list with two elements - the ID of the user and...
    if not result or not isinstance(result, list) or len(result) != 2:
        return None, None
    return user_datastore.get_user(int(result[0])), result[1]


def get_user_and_hashed_pass(request):
    """Similar to the `user_loader`, except it also return the hashed_pass

    :param request: flask's request
    :return: Return a tuple with a user object (or None) and its hashed pass
    """
    auth = request.authorization
    if auth:
        user = user_datastore.get_user(auth.username)
        hashed_pass = md5(auth.password)
    else:
        token_auth_header = current_app.config[
            'SECURITY_TOKEN_AUTHENTICATION_HEADER']
        token = request.headers.get(token_auth_header)
        if not token:
            return None, None
        user, hashed_pass = _get_user_from_token(token)

    # if user:
    #     db = current_app.extensions['sqlalchemy'].db
    #     # This hack makes sure the roles are actually loaded from the DB
    #     _ = user.roles  # NOQA
    #     _ = user.tenants  # NOQA
    #     # This is necessary to allow access after the SQLA session has closed
    #     db.make_transient(user)
    return user, hashed_pass
