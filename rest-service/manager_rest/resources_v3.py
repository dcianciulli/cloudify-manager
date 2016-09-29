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
from manager_rest.security import SecuredResource, get_tenant_manager
from manager_rest.storage import get_storage_manager
from manager_rest.resources import (marshal_with,
                                    exceptions_handled)
from manager_rest.resources_v2 import (create_filters,
                                       paginate,
                                       sortable,
                                       verify_json_content_type,
                                       verify_parameter_in_request_body)


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


class TenantUsers(SecuredResource):
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

        return get_tenant_manager().add_user_to_tenant(
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
        Remove a user from a tenant
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('username', request_json)
        verify_parameter_in_request_body('tenant_name', request_json)

        return get_tenant_manager().remove_user_from_tenant(
            request_json['username'],
            request_json['tenant_name']
        )


class TenantGroups(SecuredResource):
    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='addGroup',
        notes='Add a group to a tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Group)
    def put(self):
        """
        Add a group to a tenant
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('group_name', request_json)
        verify_parameter_in_request_body('tenant_name', request_json)

        return get_tenant_manager().add_group_to_tenant(
            request_json['group_name'],
            request_json['tenant_name']
        )

    @swagger.operation(
        responseClass=responses_v3.Tenant,
        nickname='removeGroup',
        notes='Remove a group from a tenant.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Group)
    def delete(self):
        """
        Remove a group from a tenant
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('group_name', request_json)
        verify_parameter_in_request_body('tenant_name', request_json)

        return get_tenant_manager().remove_group_from_tenant(
            request_json['group_name'],
            request_json['tenant_name']
        )


class UserGroups(SecuredResource):
    @swagger.operation(
        responseClass='List[{0}]'.format(responses_v3.Group.__name__),
        nickname="list",
        notes='returns a list of user groups.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Group)
    @create_filters(models.Group.fields)
    @paginate
    @sortable
    def get(self, _include=None, filters=None, pagination=None, sort=None,
            **kwargs):
        """
        List groups
        """
        return get_storage_manager().list_groups(
            include=_include,
            filters=filters,
            pagination=pagination,
            sort=sort)


class UserGroupsId(SecuredResource):
    @swagger.operation(
        responseClass=responses_v3.Group,
        nickname='createGroup',
        notes='Create a new group.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.Group)
    def post(self, group_name):
        """
        Create a group
        """
        group = get_storage_manager().put_group({'name': group_name})
        return group, 201


class UserGroupsUsers(SecuredResource):
    @swagger.operation(
        responseClass=responses_v3.Group,
        nickname='addUser',
        notes='Add a user to a group.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.User)
    def put(self):
        """
        Add a user to a group
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('username', request_json)
        verify_parameter_in_request_body('group_name', request_json)

        return get_tenant_manager().add_user_to_group(
            request_json['username'],
            request_json['group_name']
        )

    @swagger.operation(
        responseClass=responses_v3.Group,
        nickname='removeUser',
        notes='Remove a user from a group.'
    )
    @exceptions_handled
    @marshal_with(responses_v3.User)
    def delete(self):
        """
        Remove a user from a group
        """
        verify_json_content_type()
        request_json = request.json
        verify_parameter_in_request_body('username', request_json)
        verify_parameter_in_request_body('group_name', request_json)

        return get_tenant_manager().remove_user_from_group(
            request_json['username'],
            request_json['group_name']
        )
