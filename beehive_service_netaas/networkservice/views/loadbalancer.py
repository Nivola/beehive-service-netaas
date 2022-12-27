# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte

from flasgger import Schema
from beecell.simple import id_gen
from beehive.common.apimanager import ApiView, SwaggerApiView, ApiManagerError
from beehive.common.data import operation
from beehive_service.views import ServiceApiView, NotEmptyString
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from beehive_service_netaas.networkservice.controller import ApiNetworkService, ApiNetworkHealthMonitor, \
    ApiNetworkTargetGroup, ApiNetworkListener, ApiNetworkLoadBalancer
from marshmallow.validate import OneOf


#
# Health Monitor
#
class TagResponseSchema(Schema):
    key = fields.String(required=True, example='test', description='The key of the tag')
    value = fields.String(required=True, example='test', description='The value of the tag')


class HealthMonitorResponseSchema(Schema):
    tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True, description='Any tags '
                           'assigned to the target group')
    healthmonitorId = fields.String(required=True, example='12', description='ID of the health monitor')
    ownerId = fields.String(required=True, example='', descriptiom='ID of the account that owns the health monitor')
    nvl_ownerAlias = fields.String(required=False, example='test', data_key='nvl-ownerAlias',
                                   descriptiom='Alias of the account that owns the health monitor')
    name = fields.String(required=True, description='The name of the health monitor')
    state = fields.String(required=True, example='available', description='State of the service instance (pending | '
                          'available | transient | error)')
    protocol = fields.String(required=True, description='The protocol the load balancer uses when performing '
                             'health checks on targets')
    interval = fields.Integer(required=True, description='The approximate amount of time, in seconds, between '
                              'health checks of an individual target')
    timeout = fields.Integer(required=True, description='The amount of time, in seconds, during which no response '
                             'from a target means a failed health check')
    maxRetries = fields.Integer(required=True, description='The number of consecutive health check failures '
                                'required before considering a target unhealthy.')
    method = fields.String(required=True, description='The HTTP method to be used for health check')
    requestURI = fields.String(required=True, description='The destination for health checks on the targets.')
    expected = fields.String(required=True, description='The HTTP code the monitor expects to match in a '
                             'successful response from a target')


class DescribeHealthMonitorResponse1Schema(Schema):
    xmlns = fields.String(required=False, data_key='__xmlns')
    requestId = fields.String(required=True, allow_none=False, description='Request ID')
    healthMonitorSet = fields.Nested(HealthMonitorResponseSchema, many=True, required=True, allow_none=False,
                                     description='List of health monitor definitions')
    nvl_healthMonitorTotal = fields.Integer(required=True,  example='', description='Total number of health monitors',
                                            data_key='nvl-healthMonitorTotal')
    nextToken = fields.String(required=True,  description='The token to use to retrieve the next page of results. '
                              'This value is null')


class DescribeHealthMonitorsResponseSchema(Schema):
    DescribeHealthMonitorsResponse = fields.Nested(DescribeHealthMonitorResponse1Schema, required=True, many=False,
                                                   allow_none=False)


class DescribeHealthMonitorsRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='Account ID of the health monitor owner')
    HealthMonitorName = fields.String(required=False, context='query', description='The user-supplied health monitor '
                                      'name')
    HealthMonitorId_N = fields.List(fields.String(), required=False, allow_none=True, context='query',
                                    collection_format='multi', data_key='HealthMonitorId.N',
                                    description='One or more health monitor IDs')
    MaxResults = fields.Integer(required=False, default=10, description='Number of results per page',
                                data_key='MaxResults', context='query')
    NextToken = fields.String(required=False, default='0', description='Page number', data_key='Nvl-NextToken',
                              context='query')


class DescribeHealthMonitors(ServiceApiView):
    summary = 'Describe health monitor'
    description = 'Describe health monitor'
    tags = ['networkservice']
    definitions = {
        'DescribeHealthMonitorsResponseSchema': DescribeHealthMonitorsResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeHealthMonitorsRequestSchema)
    parameters_schema = DescribeHealthMonitorsRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeHealthMonitorsResponseSchema
        }
    })
    response_schema = DescribeHealthMonitorsResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {
            'size': data.get('MaxResults', 10),
            'page': int(data.get('NextToken', 0))
        }

        # get account
        account_id_list = data.get('owner_id_N', [])

        # get instance id
        instance_id_list = data.get('HealthMonitorId_N', [])

        # get instance name
        instance_name_list = data.get('HealthMonitorName', None)
        if instance_name_list is not None:
            instance_name_list = [instance_name_list]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get instances list
        res, total = controller.get_service_type_plugins(service_uuid_list=instance_id_list,
                                                         service_name_list=instance_name_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         plugintype=ApiNetworkHealthMonitor.plugintype,
                                                         **data_search)

        # format result
        monitor_set = [r.aws_info() for r in res]

        res = {
            'DescribeHealthMonitorsResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'healthMonitorSet': monitor_set,
                'nextToken': None,
                'healthMonitorTotal': total
            }
        }

        return res


class CreateHealthMonitorResponse2Schema(Schema):
    healthMonitorId = fields.String(required=True, allow_none=False, description='The ID of the monitor')


class CreateHealthMonitorResponse1Schema(Schema):
    HealthMonitor = fields.Nested(CreateHealthMonitorResponse2Schema, required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True, description='Request ID')


class CreateHealthMonitorResponseSchema(Schema):
    CreateHealthMonitorResponse = fields.Nested(CreateHealthMonitorResponse1Schema, required=True, allow_none=False)


class CreateHealthMonitorParamsRequestSchema(Schema):
    owner_id = fields.String(required=True, example='account-1', description='The account ID', data_key='owner-id')
    Name = fields.String(required=True, allow_none=False, description='The name of the health monitor')
    Protocol = fields.String(required=True, allow_none=False, validate=OneOf(['HTTP', 'HTTPS', 'TCP']),
                             description='The protocol the load balancer uses when performing health checks on '
                             'targets')
    Interval = fields.Integer(required=False, allow_none=True, description='The approximate amount of time, in '
                              'seconds, between health checks of an individual target')
    Timeout = fields.Integer(required=False, allow_none=True, description='The amount of time, in seconds, during '
                             'which no response from a target means a failed health check')
    MaxRetries = fields.Integer(required=False, allow_none=True, description='The number of consecutive health check '
                                'failures required before considering a target unhealthy')
    Method = fields.String(required=False, allow_none=True, validate=OneOf(['GET', 'POST', 'OPTIONS']),
                           description='The HTTP method to be used for health check')
    RequestURI = fields.String(required=False, allow_none=True, description='The destination for health checks on the '
                               'targets')
    Expected = fields.String(required=False, allow_none=True, description='The HTTP code the monitor expects to match '
                             'in a successful response from target')
    MonitorTemplate = NotEmptyString(required=False, allow_none=True, description='Health monitor template')


class CreateHealthMonitorRequestSchema(Schema):
    health_monitor = fields.Nested(CreateHealthMonitorParamsRequestSchema, context='body')


class CreateHealthMonitorBodyRequestSchema(Schema):
    body = fields.Nested(CreateHealthMonitorRequestSchema, context='body')


class CreateHealthMonitor(ServiceApiView):
    summary = 'Create health monitor'
    description = 'Create health monitor'
    tags = ['networkservice']
    definitions = {
        'CreateHealthMonitorRequestSchema': CreateHealthMonitorRequestSchema,
        'CreateHealthMonitorResponseSchema': CreateHealthMonitorResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateHealthMonitorBodyRequestSchema)
    parameters_schema = CreateHealthMonitorRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateHealthMonitorResponseSchema
        }
    })
    response_schema = CreateHealthMonitorResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get('health_monitor')
        account_id = inner_data.get('owner_id')
        name = inner_data.get('Name')
        desc = inner_data.get('Description', name)
        hm_template = inner_data.pop('MonitorTemplate', None)

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiNetworkService.plugintype)
        # get definition
        if hm_template is not None:
            service_definition = controller.get_service_def(hm_template)
        else:
            service_definition = controller.get_default_service_def(ApiNetworkHealthMonitor.plugintype)

        # create service
        plugin = controller.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=desc,
                                                    parent_plugin=parent_plugin, instance_config=data)

        res = {
            'CreateHealthMonitorResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'HealthMonitor': {
                    'healthMonitorId': plugin.instance.uuid
                }
            }
        }

        self.logger.debug('Service Aws response: %s' % res)
        return res, 202


class DeleteHealthMonitorResponseItemSchema(Schema):
    requestId = fields.String(required=True, default='The ID of the request')
    nvl_return = fields.Boolean(required=True, example=True, data_key='return')


class DeleteHealthMonitorResponseSchema(Schema):
    DeleteHealthMonitorResponse = fields.Nested(DeleteHealthMonitorResponseItemSchema, required=True, many=False,
                                                allow_none=False)


class DeleteHealthMonitorRequestSchema(Schema):
    healthMonitorId = fields.String(required=True, context='query', example='monitor-896478',
                                    description='The ID of the monitor')


class DeleteHealthMonitorBodyRequestSchema(Schema):
    body = fields.Nested(DeleteHealthMonitorRequestSchema, context='body')


class DeleteHealthMonitor(ServiceApiView):
    summary = 'Delete health monitor'
    description = 'Delete health monitor'
    tags = ['networkservice']
    definitions = {
        'DeleteHealthMonitorRequestSchema': DeleteHealthMonitorRequestSchema,
        'DeleteHealthMonitorResponseSchema': DeleteHealthMonitorResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteHealthMonitorBodyRequestSchema)
    parameters_schema = DeleteHealthMonitorRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeleteHealthMonitorResponseSchema
        }
    })
    response_schema = DeleteHealthMonitorResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        monitor_id = data.pop('healthMonitorId')
        type_plugin = controller.get_service_type_plugin(monitor_id)
        type_plugin.delete()

        res = {
            'DeleteHealthMonitorResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'return': True
            }
        }

        return res, 202


#
# Target Group
#
class TargetGroupAttachedHealthMonitorResponseSchema(Schema):
    id = fields.String(required=True, description='Health monitor ID')
    name = fields.String(required=True, description='Health monitor name')
    state = fields.String(required=True, description='Health monitor state')


class TargetGroupAttachedTargets1ResponseSchema(Schema):
    id = fields.String(required=True, description='Target ID')
    name = fields.String(required=True, description='Target name')
    state = fields.String(required=True, description='Target state')
    lb_port = fields.Integer(required=True, description='Target port for balanced traffic')
    hm_port = fields.Integer(required=True, description='Target port for health checks')
    site = fields.String(required=True, description='Target site')


class TargetGroupAttachedTargetsResponseSchema(Schema):
    Targets = fields.Nested(TargetGroupAttachedTargets1ResponseSchema, required=True, many=True, description='List of '
                            'registered targets')
    totalTargets = fields.Integer(required=True, description='The amount of registered targets')


class TargetGroupAttachmentSetResponseSchema(Schema):
    TargetSet = fields.Nested(TargetGroupAttachedTargetsResponseSchema, required=True,
                              description='Attached targets')
    HealthMonitor = fields.Nested(TargetGroupAttachedHealthMonitorResponseSchema, required=True, allow_none=True,
                                  description='Attached health monitor')


class TargetGroupResponseSchema(Schema):
    tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True)
    name = fields.String(required=True, description='The name of the health monitor')
    balancingAlgorithm = fields.String(required=True, description='The algorithm used to load balance targets')
    targetType = fields.String(required=True, description='The type of target to specify when registering targets '
                               'with the target group, e.g. vm')
    attachmentSet = fields.Nested(TargetGroupAttachmentSetResponseSchema, required=True, description='Any targets '
                                  'and/or health monitor attached to the target group')


class DescribeTargetGroupsResponse1Schema(Schema):
    xmlns = fields.String(required=False, data_key='__xmlns')
    requestId = fields.String(required=True, allow_none=False, description='Request ID')
    targetGroupSet = fields.Nested(TargetGroupResponseSchema, many=True, required=True, allow_none=False,
                                   description='List of target group definitions')
    nvl_targetGroupTotal = fields.Integer(required=True,  example='', description='Total number of target groups',
                                          data_key='nvl-targetGroupTotal')
    nextToken = fields.String(required=True, example='ednundw83ldw',
                              description='The token to use to retrieve the next page of results. This value is null')


class DescribeTargetGroupsResponseSchema(Schema):
    DescribeTargetGroupsResponse = fields.Nested(DescribeTargetGroupsResponse1Schema, required=True, many=False,
                                                 allow_none=False)


class DescribeTargetGroupsRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='Account ID of the target group owner')
    TargetGroupName = fields.String(required=False, context='query', description='The user-supplied target group name')
    TargetGroupId_N = fields.List(fields.String(), required=False, allow_none=True, context='query',
                                  collection_format='multi', data_key='TargetGroupId.N', description='The names of '
                                  'the target groups')
    MaxResults = fields.Integer(required=False, default=10, description='Number of results per page',
                                data_key='MaxResults', context='query')
    NextToken = fields.String(required=False, default='0', description='Page number', data_key='Nvl-NextToken',
                              context='query')


class DescribeTargetGroups(ServiceApiView):
    summary = 'Describe target groups'
    description = 'Describe target groups'
    tags = ['networkservice']
    definitions = {
        'DescribeTargetGroupsResponseSchema': DescribeTargetGroupsResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeTargetGroupsRequestSchema)
    parameters_schema = DescribeTargetGroupsRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeTargetGroupsResponseSchema
        }
    })
    response_schema = DescribeTargetGroupsResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {
            'size': data.get('MaxResults', 10),
            'page': int(data.get('NextToken', 0))
        }

        # get account
        account_id_list = data.get('owner_id_N', [])

        # get instance id
        instance_id_list = data.get('TargetGroupId_N', [])

        # get instance name
        instance_name_list = data.get('TargetGroupName', None)
        if instance_name_list is not None:
            instance_name_list = [instance_name_list]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get instances list
        res, total = controller.get_service_type_plugins(service_uuid_list=instance_id_list,
                                                         service_name_list=instance_name_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         plugintype=ApiNetworkTargetGroup.plugintype,
                                                         **data_search)

        # format result
        target_group_set = [r.aws_info() for r in res]

        res = {
            'DescribeTargetGroupsResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'targetGroupSet': target_group_set,
                'nextToken': None,
                'nvl-targetGroupTotal': total
            }
        }

        return res


class CreateTargetGroupResponse2Schema(Schema):
    targetGroupId = fields.String(required=True, allow_none=False, description='The ID of the target group')
    # attachmentSet = fields.Nested(TargetGroupsAttachmentSetResponseSchema, required=True, description='Any targets '
    #                               'and/or health monitor attached to the target group')
    # tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True, description='Any tags '
    #                        'assigned to the target group')


class CreateTargetGroupResponse1Schema(Schema):
    TargetGroup = fields.Nested(CreateTargetGroupResponse2Schema, required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True, description='Request ID')


class CreateTargetGroupResponseSchema(Schema):
    CreateTargetGroupResponse = fields.Nested(CreateTargetGroupResponse1Schema, required=True, allow_none=False)


class CreateTargetGroupParamsRequestSchema(Schema):
    owner_id = fields.String(required=True, example='account-1', description='The account ID', data_key='owner-id')
    Name = fields.String(required=True, allow_none=False, description='The name of the target group')
    Description = fields.String(required=False, allow_none=True, description='A description for the target group')
    BalancingAlgorithm = fields.String(required=True, allow_none=False, validate=OneOf(['round-robin', 'ip-hash',
                                       'leastconn', 'uri']), description='The algorithm used to load balance targets')
    TargetType = fields.String(required=True, allow_none=False, validate=OneOf(['vm', 'container']), description='The '
                               'type of target you must specify when registering targets to this target group')
    HealthMonitor = fields.String(required=False, allow_none=True, description='The monitor used to perform health '
                                  'checks on targets')


class CreateTargetGroupRequestSchema(Schema):
    target_group = fields.Nested(CreateTargetGroupParamsRequestSchema, context='body')


class CreateTargetGroupBodyRequestSchema(Schema):
    body = fields.Nested(CreateTargetGroupRequestSchema, context='body')


class CreateTargetGroup(ServiceApiView):
    summary = 'Create target group'
    description = 'Create target group'
    tags = ['networkservice']
    definitions = {
        'CreateTargetGroupRequestSchema': CreateTargetGroupRequestSchema,
        'CreateTargetGroupResponseSchema': CreateTargetGroupResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateTargetGroupBodyRequestSchema)
    parameters_schema = CreateTargetGroupRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateTargetGroupResponseSchema
        }
    })
    response_schema = CreateTargetGroupResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get('target_group')
        account_id = inner_data.get('owner_id')
        name = inner_data.get('Name')
        desc = inner_data.get('Description', name)

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiNetworkService.plugintype)
        # get target group definition
        service_definition = controller.get_default_service_def(ApiNetworkTargetGroup.plugintype)

        # create service
        plugin = controller.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=desc,
                                                    parent_plugin=parent_plugin, instance_config=data)

        res = {
            'CreateTargetGroupResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'TargetGroup': {
                    'targetGroupId': plugin.instance.uuid
                }
            }
        }

        self.logger.debug('Service Aws response: %s' % res)
        return res, 202


class DeleteTargetGroupResponseSchema(Schema):
    pass


class DeleteTargetGroupRequestSchema(Schema):
    targetGroupId = fields.String(required=True, context='query', example='target-group-896478',
                                  description='The ID of the target group')


class DeleteTargetGroupBodyRequestSchema(Schema):
    body = fields.Nested(DeleteTargetGroupRequestSchema, context='body')


class DeleteTargetGroup(ServiceApiView):
    summary = 'Delete target group'
    description = 'Delete target group'
    tags = ['networkservice']
    definitions = {
        'DeleteTargetGroupRequestSchema': DeleteTargetGroupRequestSchema,
        'DeleteTargetGroupResponseSchema': DeleteTargetGroupResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteTargetGroupBodyRequestSchema)
    parameters_schema = DeleteTargetGroupRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeleteTargetGroupResponseSchema
        }
    })
    response_schema = DeleteTargetGroupResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        target_group_id = data.pop('targetGroupId')
        type_plugin = controller.get_service_type_plugin(target_group_id)
        type_plugin.delete()

        res = {
            'DeleteTargetGroupResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'return': True
            }
        }

        return res, 202


class RegisterTargets1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', description='Request ID')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='Active task ID')


class RegisterTargetsResponseSchema(Schema):
    RegisterTargetsResponse = fields.Nested(RegisterTargets1ResponseSchema, required=True, many=False, allow_none=False)


class RegisterTargets2RequestSchema(Schema):
    Id = fields.String(required=True, description='The ID of the target')
    LbPort = fields.Integer(required=False, allow_none=True, description='The port on which target receives traffic')
    HmPort = fields.Integer(required=False, allow_none=True, description='The port on which target is listening for '
                            'health check')


class RegisterTargets1RequestSchema(Schema):
    TargetGroupId = fields.String(required=True, description='The ID of the target group')
    Targets = fields.Nested(RegisterTargets2RequestSchema, required=True, allow_none=False, many=True,
                            description='List of targets')


class RegisterTargetsRequestSchema(Schema):
    target_group = fields.Nested(RegisterTargets1RequestSchema, context='body')


class RegisterTargetsBodyRequestSchema(Schema):
    body = fields.Nested(RegisterTargetsRequestSchema, context='body')


class RegisterTargets(ServiceApiView):
    summary = 'Register targets on target group'
    description = 'Register targets on target group'
    tags = ['networkservice']
    definitions = {
        'RegisterTargetsRequestSchema': RegisterTargetsRequestSchema,
        'RegisterTargetsResponseSchema': RegisterTargetsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(RegisterTargetsBodyRequestSchema)
    parameters_schema = RegisterTargetsRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': RegisterTargetsResponseSchema
        }
    })
    response_schema = RegisterTargetsResponseSchema

    def put(self, controller, data, *args, **kwargs):
        inner_data = data.get('target_group')
        target_group_id = inner_data.pop('TargetGroupId')
        targets = inner_data.pop('Targets')

        type_plugin = controller.get_service_type_plugin(target_group_id)
        type_plugin.register_targets(targets)

        res = {
            'RegisterTargetsResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class DeregisterTargets1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', description='Request ID')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='Active task ID')


class DeregisterTargetsResponseSchema(Schema):
    DeregisterTargetsResponse = fields.Nested(DeregisterTargets1ResponseSchema, required=True, many=False,
                                              allow_none=False)


class DeregisterTargets2RequestSchema(Schema):
    TargetId = fields.String(required=True, description='The ID of the target')


class DeregisterTargets1RequestSchema(Schema):
    TargetGroupId = fields.String(required=True, description='The ID of the target group')
    Targets = fields.Nested(DeregisterTargets2RequestSchema, required=True, allow_none=False, many=True,
                            description='List of targets')


class DeregisterTargetsRequestSchema(Schema):
    target_group = fields.Nested(DeregisterTargets1RequestSchema, context='body')


class DeregisterTargetsBodyRequestSchema(Schema):
    body = fields.Nested(DeregisterTargetsRequestSchema, context='body')


class DeregisterTargets(ServiceApiView):
    summary = 'Deregister target from target group'
    description = 'Deregister target from target group'
    tags = ['networkservice']
    definitions = {
        'DeregisterTargetsRequestSchema': DeregisterTargetsRequestSchema,
        'DeregisterTargetsResponseSchema': DeregisterTargetsResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeregisterTargetsBodyRequestSchema)
    parameters_schema = DeregisterTargetsRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeregisterTargetsResponseSchema
        }
    })
    response_schema = DeregisterTargetsResponseSchema

    def put(self, controller, data, *args, **kwargs):
        inner_data = data.get('target_group')
        target_group_id = inner_data.pop('TargetGroupId')
        targets = inner_data.pop('Targets')

        type_plugin = controller.get_service_type_plugin(target_group_id)
        type_plugin.deregister_targets(targets)

        res = {
            'DeregisterTargetsResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class RegisterHealthMonitor1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', description='Request ID')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='Active task ID')


class RegisterHealthMonitorResponseSchema(Schema):
    RegisterHealthMonitorResponse = fields.Nested(RegisterHealthMonitor1ResponseSchema, required=True, many=False,
                                                allow_none=False)


class RegisterHealthMonitor1RequestSchema(Schema):
    TargetGroupId = fields.String(required=True, allow_none=False, description='The ID of the target group')
    HealthMonitorId = fields.String(required=True, allow_none=False, description='The ID of the health monitor')


class RegisterHealthMonitorRequestSchema(Schema):
    target_group = fields.Nested(RegisterHealthMonitor1RequestSchema, context='body')


class RegisterHealthMonitorBodyRequestSchema(Schema):
    body = fields.Nested(RegisterHealthMonitorRequestSchema, context='body')


class RegisterHealthMonitor(ServiceApiView):
    summary = 'Register health monitor on target group'
    description = 'Register health monitor on target group'
    tags = ['networkservice']
    definitions = {
        'RegisterHealthMonitorRequestSchema': RegisterHealthMonitorRequestSchema,
        'RegisterHealthMonitorResponseSchema': RegisterHealthMonitorResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(RegisterHealthMonitorBodyRequestSchema)
    parameters_schema = RegisterHealthMonitorRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': RegisterHealthMonitorResponseSchema
        }
    })
    response_schema = RegisterHealthMonitorResponseSchema

    def put(self, controller, data, *args, **kwargs):
        inner_data = data.get('target_group')
        target_group_id = inner_data.pop('TargetGroupId')
        monitor_id = inner_data.pop('HealthMonitorId')

        type_plugin = controller.get_service_type_plugin(target_group_id)
        type_plugin.register_health_monitor(monitor_id)

        res = {
            'RegisterHealthMonitorResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class DeregisterHealthMonitor1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', description='Request ID')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='Active task ID')


class DeregisterHealthMonitorResponseSchema(Schema):
    DeregisterHealthMonitorResponse = fields.Nested(DeregisterHealthMonitor1ResponseSchema, required=True, many=False,
                                                    allow_none=False)


class DeregisterHealthMonitor1RequestSchema(Schema):
    TargetGroupId = fields.String(required=True, description='The ID of the target group')


class DeregisterHealthMonitorRequestSchema(Schema):
    target_group = fields.Nested(DeregisterHealthMonitor1RequestSchema, context='body')


class DeregisterHealthMonitorBodyRequestSchema(Schema):
    body = fields.Nested(DeregisterHealthMonitorRequestSchema, context='body')


class DeregisterHealthMonitor(ServiceApiView):
    summary = 'Deregister health monitor from target group'
    description = 'Deregister health monitor from target group'
    tags = ['networkservice']
    definitions = {
        'DeregisterHealthMonitorRequestSchema': DeregisterHealthMonitorRequestSchema,
        'DeregisterHealthMonitorResponseSchema': DeregisterHealthMonitorResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeregisterHealthMonitorBodyRequestSchema)
    parameters_schema = DeregisterHealthMonitorRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeregisterHealthMonitorResponseSchema
        }
    })
    response_schema = DeregisterHealthMonitorResponseSchema

    def put(self, controller, data, *args, **kwargs):
        inner_data = data.get('target_group')
        target_group_id = inner_data.pop('TargetGroupId')

        type_plugin = controller.get_service_type_plugin(target_group_id)
        type_plugin.deregister_health_monitor()

        res = {
            'DeregisterHealthMonitorResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


#
# Listener
#
class GatewayApiTagResponseSchema(Schema):
    key = fields.String(required=True, example='test', description='The key of the tag')
    value = fields.String(required=True, example='test', description='The value of the tag')


class ListenerResponseSslSchema(Schema):
    certificate = fields.String(required=False, allow_none=True, description='Certificate ID')
    cipher = fields.String(required=False, allow_none=True, description='Cipher suite')


class ListenerPersistenceResponseSchema(Schema):
    method = fields.String(required=False, allow_none=True, description='Persistence criteria used by load balancer')
    cookie_name = fields.String(required=False, allow_none=True, description='The name of the cookie when cookie-based '
                                'persistence is adopted', data_key='cookieName')
    cookie_mode = fields.String(required=False, allow_none=True, description='The way the load balancer manages '
                                'cookie-based persistence', data_key='cookieMode')
    expiration_time = fields.Integer(required=False, allow_none=True, description='Persistence expiration time',
                                     data_key='expirationTime')


class ListenerResponseSchema(Schema):
    tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True)
    listenerId = fields.String(required=True, example='12', description='Listener ID')
    ownerId = fields.String(required=True, example='', descriptiom='ID of the account that owns the listener')
    nvl_ownerAlias = fields.String(required=False, example='test', data_key='nvl-ownerAlias',
                                   descriptiom='Alias of the account that owns the listener')
    name = fields.String(required=True, description='The name of the listener')
    state = fields.String(required=True, example='available', description='State of the service instance (pending | '
                          'available | transient | error)')
    trafficType = fields.String(required=True, allow_none=False, desctiption='The way the load balancer processes '
                                'the traffic directed to destination servers')
    persistence = fields.Nested(ListenerPersistenceResponseSchema, required=False, allow_none=True,
                                description='Set of parameters describing how load balancer handles the persistence')
    clientSSL = fields.Nested(ListenerResponseSslSchema, required=False, allow_none=True, description='Set of SSL '
                              'configuration for the client')
    serverSSL = fields.Nested(ListenerResponseSslSchema, required=False, allow_none=True, description='Set of SSL '
                              'configuration for the server')
    insertXForwardedFor = fields.Boolean(required=False, allow_none=True, description='Flag to instruct load '
                                         'balancer whether X-Forwarded-For header must be appended in the request')
    urlRedirect = fields.String(required=False, allow_none=True, description='The URL to redirect client requests')


class DescribeListenerResponse1Schema(Schema):
    xmlns = fields.String(required=False, data_key='__xmlns')
    requestId = fields.String(required=True, allow_none=False, description='Request ID')
    listenerSet = fields.Nested(ListenerResponseSchema, many=True, required=True, allow_none=False,
                                description='List of listener definitions')
    listenerTotal = fields.Integer(required=True,  example='', description='Total number of listeners')
    nextToken = fields.String(required=True,  description='The token to use to retrieve the next page of results. '
                              'This value is null')


class DescribeListenersResponseSchema(Schema):
    DescribeListenersResponse = fields.Nested(DescribeListenerResponse1Schema, required=True, many=False,
                                              allow_none=False)


class DescribeListenersRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='Account ID of the listener owner')
    ListenerName = fields.String(required=False, context='query', description='The user-supplied listener name')
    ListenerId_N = fields.List(fields.String(), required=False, allow_none=True, context='query',
                               collection_format='multi', description='One or more listener IDs',
                               data_key='ListenerId.N')
    MaxResults = fields.Integer(required=False, default=10, description='Number of results per page',
                                data_key='MaxResults', context='query')
    NextToken = fields.String(required=False, default='0', description='Page number', data_key='Nvl-NextToken',
                              context='query')


class DescribeListeners(ServiceApiView):
    summary = 'Describe listener'
    description = 'Describe listener'
    tags = ['networkservice']
    definitions = {
        'DescribeListenersResponseSchema': DescribeListenersResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeListenersRequestSchema)
    parameters_schema = DescribeListenersRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeListenersResponseSchema
        }
    })
    response_schema = DescribeListenersResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {
            'size': data.get('MaxResults', 10),
            'page': int(data.get('NextToken', 0))
        }

        # get account
        account_id_list = data.get('owner_id_N', [])

        # get instance id
        instance_id_list = data.get('ListenerId_N', [])

        # get instance name
        instance_name_list = data.get('ListenerName', None)
        if instance_name_list is not None:
            instance_name_list = [instance_name_list]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get instances list
        res, total = controller.get_service_type_plugins(service_uuid_list=instance_id_list,
                                                         service_name_list=instance_name_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         plugintype=ApiNetworkListener.plugintype,
                                                         **data_search)

        # format result
        listener_set = [r.aws_info() for r in res]

        res = {
            'DescribeListenersResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'listenerSet': listener_set,
                'nextToken': None,
                'listenerTotal': total
            }
        }

        return res


class CreateListenerResponse2Schema(Schema):
    listenerId = fields.String(required=True, allow_none=False, description='The ID of the listener')


class CreateListenerResponse1Schema(Schema):
    Listener = fields.Nested(CreateListenerResponse2Schema, required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True, description='Request ID')


class CreateListenerResponseSchema(Schema):
    CreateListenerResponse = fields.Nested(CreateListenerResponse1Schema, required=True, allow_none=False)


class CreateListenerParamsRequestSchema(Schema):
    owner_id = fields.String(required=True, example='account-1', description='The account ID', data_key='owner-id')
    Name = fields.String(required=True, allow_none=False, description='The name of the listener')
    Description = fields.String(required=False, allow_none=True, description='A description for the listener')
    TrafficType = fields.String(required=True, allow_none=False, validate=OneOf(['tcp', 'http', 'ssl-passthrough',
                                'https-offloading', 'https-end-to-end']), description='The way the load balancer '
                                'processes the traffic directed to destination servers')
    Persistence = fields.String(required=False, allow_none=True, validate=OneOf(['sourceip', 'cookie',
                                'ssl-sessionid']), description='Load balancer persistence criteria')
    CookieName = fields.String(required=False, allow_none=True, description='The name of the cookie when cookie-based '
                               'persistence is adopted')
    CookieMode = fields.String(required=False, allow_none=True, description='The way the load balancer manages '
                               'cookie-based persistence')
    ExpireTime = fields.Integer(required=False, allow_none=True, description='Persistence expiration time in seconds')
    ClientCertificate = fields.String(required=False, allow_none=True, description='Client certificate')
    ServerCertificate = fields.String(required=False, allow_none=True, description='Server certificate')
    ClientCipher = fields.String(required=False, allow_none=True, description='Cipher suite used by client')
    ServerCipher = fields.String(required=False, allow_none=True, description='Cipher suite used by server')
    InsertXForwardedFor = fields.Boolean(required=False, allow_none=True, description='A flag to instruct load '
                                         'balancer to append X-Forwarded-For header in the requests to the backend '
                                         'servers')
    URLRedirect = fields.String(required=False, allow_none=True, description='The URL to redirect client requests')
    ListenerTemplate = NotEmptyString(required=False, allow_none=True, description='Listener template')


class CreateListenerRequestSchema(Schema):
    listener = fields.Nested(CreateListenerParamsRequestSchema, context='body')


class CreateListenerBodyRequestSchema(Schema):
    body = fields.Nested(CreateListenerRequestSchema, context='body')


class CreateListener(ServiceApiView):
    summary = 'Create listener'
    description = 'Create listener'
    tags = ['networkservice']
    definitions = {
        'CreateListenerRequestSchema': CreateListenerRequestSchema,
        'CreateListenerResponseSchema': CreateListenerResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateListenerBodyRequestSchema)
    parameters_schema = CreateListenerRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateListenerResponseSchema
        }
    })
    response_schema = CreateListenerResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get('listener')
        account_id = inner_data.get('owner_id')
        name = inner_data.get('Name')
        desc = inner_data.get('Description', name)
        li_template = inner_data.pop('ListenerTemplate', None)

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiNetworkService.plugintype)
        # get definition
        if li_template is not None:
            service_definition = controller.get_service_def(li_template)
        else:
            service_definition = controller.get_default_service_def(ApiNetworkListener.plugintype)

        # create service
        plugin = controller.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=desc,
                                                    parent_plugin=parent_plugin, instance_config=data)

        res = {
            'CreateListenerResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'Listener': {
                    'listenerId': plugin.instance.uuid
                }
            }
        }

        self.logger.debug('Service Aws response: %s' % res)
        return res, 202


class DeleteListenerResponseItemSchema(Schema):
    requestId = fields.String(required=True, default='The ID of the request')
    nvl_return = fields.Boolean(required=True, example=True, data_key='return')


class DeleteListenerResponseSchema(Schema):
    DeleteListenerResponse = fields.Nested(DeleteListenerResponseItemSchema, required=True, many=False,
                                           allow_none=False)


class DeleteListenerRequestSchema(Schema):
    listenerId = fields.String(required=True, context='query', example='listener-896478',
                               description='The ID of the listener')


class DeleteListenerBodyRequestSchema(Schema):
    body = fields.Nested(DeleteListenerRequestSchema, context='body')


class DeleteListener(ServiceApiView):
    summary = 'Delete listener'
    description = 'Delete listener'
    tags = ['networkservice']
    definitions = {
        'DeleteListenerRequestSchema': DeleteListenerRequestSchema,
        'DeleteListenerResponseSchema': DeleteListenerResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteListenerBodyRequestSchema)
    parameters_schema = DeleteListenerRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeleteListenerResponseSchema
        }
    })
    response_schema = DeleteListenerResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        listener_id = data.pop('listenerId')
        type_plugin = controller.get_service_type_plugin(listener_id)
        type_plugin.delete()

        res = {
            'DeleteListenerResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'return': True
            }
        }

        return res, 202


#
# Load Balancer
#
class LoadBalancerAttachedListenerResponseSchema(Schema):
    id = fields.String(required=True, description='Listener ID')
    name = fields.String(required=True, description='Listener name')
    state = fields.String(required=True, description='Listener state')


class LoadBalancerAttachedTargetGroupResponseSchema(Schema):
    id = fields.String(required=True, description='Target group ID')
    name = fields.String(required=True, description='Target group name')
    state = fields.String(required=True, description='Target group state')


class LoadBalancerAttachmentSetResponseSchema(Schema):
    Listener = fields.Nested(LoadBalancerAttachedListenerResponseSchema, required=True, allow_none=True,
                             description='Attached listener')
    TargetGroup = fields.Nested(LoadBalancerAttachedTargetGroupResponseSchema, required=True, allow_none=True,
                                description='Attached target group')


class LoadBalancerResponseSchema(Schema):
    tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True)
    name = fields.String(required=True, description='The name of the health monitor')
    vpcId = fields.String(required=True, description='ID of the VPC')
    subnetId = fields.String(required=True, description='ID of the subnet')
    protocol = fields.String(required=True, description='The protocol for connections from clients to load balancer')
    virtualIP = fields.String(required=True, description='Virtual IP exposed by load balancer')
    isVIPStatic = fields.String(required=True, description='True if the load balancer frontend IP address has been '
                                'provided by the user as input parameter; False otherwise')
    port = fields.Integer(required=True, description='The port on which the load balancer is listening')
    maxConn = fields.Integer(required=False, description='Maximum concurrent connections')
    maxConnRate = fields.Integer(required=False, description='Maximum incoming connection requests per second')
    attachmentSet = fields.Nested(LoadBalancerAttachmentSetResponseSchema, required=True, description='Listener and '
                                  'target group attached to the load balancer')


class DescribeLoadBalancersResponse1Schema(Schema):
    xmlns = fields.String(required=False, data_key='__xmlns')
    requestId = fields.String(required=True, allow_none=False, description='Request ID')
    loadBalancerSet = fields.Nested(LoadBalancerResponseSchema, many=True, required=True, allow_none=False,
                                    description='List of load balancer definitions')
    nvl_loadBalancerTotal = fields.Integer(required=True,  example='', description='Total number of load balancers',
                                           data_key='nvl-loadBalancerTotal')
    nextToken = fields.String(required=True, example='ednundw83ldw', description='The token to use to retrieve the '
                              'next page of results. This value is null')


class DescribeLoadBalancersResponseSchema(Schema):
    DescribeLoadBalancersResponse = fields.Nested(DescribeLoadBalancersResponse1Schema, required=True, many=False,
                                                  allow_none=False)


class DescribeLoadBalancersRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='Account ID of the target group owner')
    LoadBalancerName = fields.String(required=False, context='query', description='The user-supplied load balancer '
                                     'name')
    LoadBalancerId_N = fields.List(fields.String(), required=False, allow_none=True, context='query',
                                   collection_format='multi', data_key='LoadBalancerId.N', description='The names of '
                                   'the load balancers')
    MaxResults = fields.Integer(required=False, default=10, description='Number of results per page',
                                data_key='MaxResults', context='query')
    NextToken = fields.String(required=False, default='0', description='Page number', data_key='Nvl-NextToken',
                              context='query')


class DescribeLoadBalancers(ServiceApiView):
    summary = 'Describe load balancers'
    description = 'Describe load balancers'
    tags = ['networkservice']
    definitions = {
        'DescribeLoadBalancersResponseSchema': DescribeLoadBalancersResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeLoadBalancersRequestSchema)
    parameters_schema = DescribeLoadBalancersRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeLoadBalancersResponseSchema
        }
    })
    response_schema = DescribeLoadBalancersResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {
            'size': data.get('MaxResults', 10),
            'page': int(data.get('NextToken', 0))
        }

        # get account
        account_id_list = data.get('owner_id_N', [])

        # get instance id
        instance_id_list = data.get('LoadBalancerId_N', [])

        # get instance name
        instance_name_list = data.get('LoadBalancerName', None)
        if instance_name_list is not None:
            instance_name_list = [instance_name_list]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get instances list
        res, total = controller.get_service_type_plugins(service_uuid_list=instance_id_list,
                                                         service_name_list=instance_name_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         plugintype=ApiNetworkLoadBalancer.plugintype,
                                                         **data_search)

        # format result
        load_balancer_set = [r.aws_info() for r in res]

        res = {
            'DescribeLoadBalancersResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'loadBalancerSet': load_balancer_set,
                'nextToken': None,
                'nvl-loadBalancerTotal': total
            }
        }

        return res


class CreateLoadBalancerResponse2Schema(Schema):
    loadBalancerId = fields.String(required=True, allow_none=False, description='The ID of the load balancer')
    # attachmentSet = fields.Nested(LoadBalancersAttachmentSetResponseSchema, required=True, description='Any listener '
    #                               'and target group attached to the load balancer')
    # tagSet = fields.Nested(TagResponseSchema, many=True, required=False, allow_none=True, description='Any tags '
    #                        'assigned to the load balancer')


class CreateLoadBalancerResponse1Schema(Schema):
    LoadBalancer = fields.Nested(CreateLoadBalancerResponse2Schema, required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True, description='Request ID')


class CreateLoadBalancerResponseSchema(Schema):
    CreateLoadBalancerResponse = fields.Nested(CreateLoadBalancerResponse1Schema, required=True, allow_none=False)


class CreateLoadBalancerParamsRequestSchema(Schema):
    owner_id = fields.String(required=True, description='The account ID', data_key='owner-id')
    Name = fields.String(required=True, allow_none=False, description='The name of the target group')
    Description = fields.String(required=False, allow_none=True, description='A description for the target group')
    SubnetId = fields.String(required=True, allow_none=False, description='ID of the subnet')
    Protocol = fields.String(required=True, allow_none=False, validate=OneOf(['HTTP', 'HTTPS']), description='The '
                             'protocol for connections from clients to load balancer')
    StaticIP = fields.String(required=False, allow_none=True, description='The frontend IP address of the load '
                             'balancer provided by the user and not determined by the orchestration system')
    Port = fields.Integer(required=True, allow_none=False, description='The port on which the load balancer is '
                          'listening')
    Listener = fields.String(required=True, allow_none=False, description='ID of the listener')
    TargetGroup = fields.String(required=True, allow_none=False, description='ID of the target group')
    MaxConnections = fields.Integer(required=False, allow_none=True, description='Maximum concurrent connections')
    MaxConnectionRate = fields.Integer(required=False, allow_none=True, description='Maximum incoming connection '
                                       'requests per second')


class CreateLoadBalancerRequestSchema(Schema):
    load_balancer = fields.Nested(CreateLoadBalancerParamsRequestSchema, context='body')


class CreateLoadBalancerBodyRequestSchema(Schema):
    body = fields.Nested(CreateLoadBalancerRequestSchema, context='body')


class CreateLoadBalancer(ServiceApiView):
    summary = 'Create load balancer'
    description = 'Create load balancer'
    tags = ['networkservice']
    definitions = {
        'CreateLoadBalancerRequestSchema': CreateLoadBalancerRequestSchema,
        'CreateLoadBalancerResponseSchema': CreateLoadBalancerResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateLoadBalancerBodyRequestSchema)
    parameters_schema = CreateLoadBalancerRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateLoadBalancerResponseSchema
        }
    })
    response_schema = CreateLoadBalancerResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get('load_balancer')
        account_id = inner_data.get('owner_id')
        name = inner_data.get('Name')
        desc = inner_data.get('Description', name)

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiNetworkService.plugintype)
        # get definition
        service_definition = controller.get_default_service_def(ApiNetworkLoadBalancer.plugintype)

        # create service
        data['computeZone'] = parent_plugin.resource_uuid
        plugin = controller.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=desc,
                                                    parent_plugin=parent_plugin, instance_config=data)

        res = {
            'CreateLoadBalancerResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'LoadBalancer': {
                    'loadBalancerId': plugin.instance.uuid
                }
            }
        }

        self.logger.debug('Service Aws response: %s' % res)
        return res, 202


class DeleteLoadBalancerResponseSchema(Schema):
    pass


class DeleteLoadBalancerRequestSchema(Schema):
    loadBalancerId = fields.String(required=True, context='query', example='load-balancer-896478',
                                   description='The ID of the load balancer')


class DeleteLoadBalancerBodyRequestSchema(Schema):
    body = fields.Nested(DeleteLoadBalancerRequestSchema, context='body')


class DeleteLoadBalancer(ServiceApiView):
    summary = 'Delete load balancer'
    description = 'Delete load balancer'
    tags = ['networkservice']
    definitions = {
        'DeleteLoadBalancerRequestSchema': DeleteLoadBalancerRequestSchema,
        'DeleteLoadBalancerResponseSchema': DeleteLoadBalancerResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteLoadBalancerBodyRequestSchema)
    parameters_schema = DeleteLoadBalancerRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeleteLoadBalancerResponseSchema
        }
    })
    response_schema = DeleteLoadBalancerResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        load_balancer_id = data.pop('loadBalancerId')
        type_plugin = controller.get_service_type_plugin(load_balancer_id)
        self.logger.warning('____delete.type_plugin={}'.format(type_plugin))
        type_plugin.delete()

        res = {
            'DeleteLoadBalancerResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'return': True
            }
        }

        return res, 202


class NetworkLoadBalancerAPI(ApiView):
    @staticmethod
    def register_api(module, rules=None, **kwargs):
        base = module.base_path + '/networkservices/loadbalancer'
        rules = [
            ('%s/healthmonitor/describehealthmonitors' % base, 'GET', DescribeHealthMonitors, {}),
            ('%s/healthmonitor/createhealthmonitor' % base, 'POST', CreateHealthMonitor, {}),
            ('%s/healthmonitor/deletehealthmonitor' % base, 'DELETE', DeleteHealthMonitor, {}),

            ('%s/targetgroup/describetargetgroups' % base, 'GET', DescribeTargetGroups, {}),
            ('%s/targetgroup/createtargetgroup' % base, 'POST', CreateTargetGroup, {}),
            ('%s/targetgroup/deletetargetgroup' % base, 'DELETE', DeleteTargetGroup, {}),
            ('%s/targetgroup/registertargets' % base, 'PUT', RegisterTargets, {}),
            ('%s/targetgroup/deregistertargets' % base, 'PUT', DeregisterTargets, {}),
            ('%s/targetgroup/registerhealthmonitor' % base, 'PUT', RegisterHealthMonitor, {}),
            ('%s/targetgroup/deregisterhealthmonitor' % base, 'PUT', DeregisterHealthMonitor, {}),

            ('%s/listener/describelisteners' % base, 'GET', DescribeListeners, {}),
            ('%s/listener/createlistener' % base, 'POST', CreateListener, {}),
            ('%s/listener/deletelistener' % base, 'DELETE', DeleteListener, {}),

            ('%s/describeloadbalancers' % base, 'GET', DescribeLoadBalancers, {}),
            ('%s/createloadbalancer' % base, 'POST', CreateLoadBalancer, {}),
            ('%s/deleteloadbalancer' % base, 'DELETE', DeleteLoadBalancer, {}),
            # ('%s/applyloadbalancer' % base, 'POST', ApplyLoadBalancer, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
