#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
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
#

from flask import request
from flask_security import current_user
from flask_restful_swagger import swagger

from manager_rest import responses_v3
from manager_rest.storage import models
from manager_rest.security import SecuredResource
from manager_rest.storage import get_storage_manager
from manager_rest.resources import (marshal_with,
                                    exceptions_handled)
from manager_rest.resources_v2 import (create_filters,
                                       paginate,
                                       sortable,
                                       verify_json_content_type,
                                       verify_parameter_in_request_body)
from manager_rest.security.user_handler import (add_user_to_tenant,
                                                remove_user_from_tenant)


class Tenants(SecuredResource):
    @swagger.operation(
        responseClass='List[{0}]'.format(responses_v3.Tenant.__name__),
        nickname="list",
        notes='returns a list of tenants.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Tenant)
    @create_filters(models.Tenant.fields)
    @paginate
    @sortable
    def get(self, _include=None, filters=None, pagination=None, sort=None,
            **kwargs):
        """
        List tenants
        """
        filters = filters or {}
        filters['id'] = [tenant.id for tenant in current_user.tenants]
        return get_storage_manager().list_tenants(
            include=_include,
            filters=filters,
            pagination=pagination,
            sort=sort)

    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='addUser',
        notes='Add a user to a tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.User)
    def put(self):
        """
        Add a user to a tenant
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('username', request_json)
        verify_parameter_in_request_body('tenant_name', request_json)

        return add_user_to_tenant(
            request_json['username'],
            request_json['tenant_name']
        )

    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='removeUser',
        notes='Remove a user from a tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.User)
    def delete(self):
        """
        Add a user to a tenant
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('username', request_json)
        verify_parameter_in_request_body('tenant_name', request_json)

        return remove_user_from_tenant(
            request_json['username'],
            request_json['tenant_name']
        )


class TenantsId(SecuredResource):
    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='createTenant',
        notes='Create a new tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Tenant)
    def post(self, tenant_name):
        """
        Create a tenant
        """
        tenant = get_storage_manager().put_tenant({'name': tenant_name})
        return tenant, 201

    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='deleteTenant',
        notes='Delete a tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Tenant)
    def delete(self, tenant_name):
        """
        Create a tenant
        """
        tenant = get_storage_manager().put_tenant({'name': tenant_name})
        return tenant, 200
