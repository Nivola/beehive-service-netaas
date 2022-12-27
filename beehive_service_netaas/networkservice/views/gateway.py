# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte

from flasgger import Schema
from beecell.simple import id_gen
from beehive.common.apimanager import ApiView, SwaggerApiView
from beehive.common.data import operation
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from beehive_service_netaas.networkservice import ApiNetworkGateway, ApiNetworkService


class GatewayApiTagResponseSchema(Schema):
    key = fields.String(required=True, example='test', description='the key of the tag')
    value = fields.String(required=True, example='test', description='the value of the tag')


class GatewayApiAttachedVpcResponseSchema(Schema):
    state = fields.String(required=True, example='account1',
                          description='the current state of the attachment. For an internet gateway, the state is '
                                      'available when attached to a VPC; otherwise, this value is not returned.')
    vpcId = fields.String(required=True, example='eur89', description='id of the vpc')
    nvl_vpcName = fields.String(required=False, example='vpc1', data_key='nvl-vpcName', description='name of the vpc')


class InternetGatewaysResponseSchema(Schema):
    tagSet = fields.Nested(GatewayApiTagResponseSchema, many=True, required=False, allow_none=True)
    attachmentSet = fields.Nested(GatewayApiAttachedVpcResponseSchema, required=False,
                                  description='Any VPCs attached to the internet gateway')
    internetGatewayId = fields.String(required=True, example='12', description='id of the gateway')
    ownerId = fields.String(required=True, example='', descriptiom='ID of the account that owns the gateway')
    nvl_ownerAlias = fields.String(required=False, example='test', data_key='nvl-ownerAlias',
                                   descriptiom='alias of the account that owns the gateway')
    nvl_name = fields.String(required=False, example='test', descriptiom='gateway name', data_key='nvl-name')
    nvl_state = fields.String(required=False, example='pending', data_key='nvl-state',
                              description='state of the VPC (pending | available | transient | error)')


class DescribeInternetGatewaysResponse1Schema(Schema):
    requestId = fields.String(required=True, example='ednundw83ldw', description='request id')
    internetGatewaySet = fields.Nested(InternetGatewaysResponseSchema, many=True, required=True,
                                       description='list of gateway definition')
    nvl_internetGatewayTotal = fields.Integer(required=True,  example='', description='total number of subnet',
                                              data_key='nvl-internetGatewayTotal')
    nextToken = fields.String(required=True, example='ednundw83ldw',
                              description='The token to use to retrieve the next page of results. This value is null')


class DescribeInternetGatewaysResponseSchema(Schema):
    DescribeInternetGatewaysResponse = fields.Nested(DescribeInternetGatewaysResponse1Schema, required=True,
                                                     many=False, allow_none=False)


class DescribeInternetGatewaysRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='account ID of the gateway owner')
    InternetGatewayId_N = fields.List(fields.String(example=''), required=False, allow_none=False, context='query',
                                      collection_format='multi', data_key='InternetGatewayId.N',
                                      description='One or more internet gateway IDs')
    MaxResults = fields.Integer(required=False, default=10, description='', data_key='MaxResults', context='query')
    NextToken = fields.String(required=False, default='0', description='', data_key='NextToken', context='query')


class DescribeInternetGateways(ServiceApiView):
    summary = 'Describe network gateway'
    description = 'Describe network gateway'
    tags = ['networkservice']
    definitions = {
        'DescribeInternetGatewaysResponseSchema': DescribeInternetGatewaysResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeInternetGatewaysRequestSchema)
    parameters_schema = DescribeInternetGatewaysRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeInternetGatewaysResponseSchema
        }
    })
    response_schema = DescribeInternetGatewaysResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {}
        data_search['size'] = data.get('MaxResults', 10)
        data_search['page'] = int(data.get('NextToken', 0))

        # check Account
        account_id_list = data.get('owner_id_N', [])

        # get gateway identifier
        gateway_id_list = data.get('InternetGatewayId_N', [])

        # # get status
        # status_mapping = {
        #     'pending': SrvStatusType.PENDING,
        #     'available': SrvStatusType.ACTIVE,
        # }
        #
        # status_name_list = None
        # status_list = data.get('state_N', None)
        # if status_list is not None:
        #     status_name_list = [status_mapping[i] for i in status_list if i in status_mapping.keys()]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get gateways list
        res, total = controller.get_service_type_plugins(service_uuid_list=gateway_id_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         # service_status_name_list=status_name_list,
                                                         plugintype=ApiNetworkGateway.plugintype,
                                                         **data_search)

        # format result
        gateways_set = [r.aws_info() for r in res]

        res = {
            'DescribeInternetGatewaysResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'internetGatewaySet': gateways_set,
                'nextToken': None,
                'nvl-internetGatewayTotal': total
            }
        }
        return res


class CreateInternetGatewayApiResponse2Schema(Schema):
    internetGatewayId = fields.String(required=True, example='igw-eaad4883', description='id of the gateway')
    ownerId = fields.String(required=True, example='account1', description='id of the owner account')
    attachmentSet = fields.Nested(GatewayApiAttachedVpcResponseSchema, required=False,
                                  description='Any VPCs attached to the internet gateway')
    tagSet = fields.Nested(GatewayApiTagResponseSchema, required=False,
                           description='Any tags assigned to the internet gateway')


class CreateInternetGatewayApiResponse1Schema(Schema):
    internetGateway = fields.Nested(CreateInternetGatewayApiResponse2Schema, required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class CreateInternetGatewayApiResponseSchema(Schema):
    CreateInternetGatewayResponse = fields.Nested(CreateInternetGatewayApiResponse1Schema, required=True,
                                                  allow_none=False)


class CreateInternetGatewayApiParamRequestSchema(Schema):
    owner_id = fields.String(required=True, example='', description='account id', data_key='owner-id')
    Nvl_GatewayType = fields.String(required=False, missing=None, description='gateway template')
    # TagSpecification_N = fields.Nested(TagSpecificationMappingApiRequestSchema, required=False, many=True,
    #                                    allow_none=False, data_key='TagSpecification.N',
    #                                    description='The tags to apply to the resources during launch')


class CreateInternetGatewayApiRequestSchema(Schema):
    gateway = fields.Nested(CreateInternetGatewayApiParamRequestSchema, context='body')


class CreateInternetGatewayApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateInternetGatewayApiRequestSchema, context='body')


class CreateInternetGateway(ServiceApiView):
    summary = 'Create network gateway'
    description = 'Create network gateway'
    tags = ['networkservice']
    definitions = {
        'CreateInternetGatewayApiRequestSchema': CreateInternetGatewayApiRequestSchema,
        'CreateInternetGatewayApiResponseSchema': CreateInternetGatewayApiResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateInternetGatewayApiBodyRequestSchema)
    parameters_schema = CreateInternetGatewayApiRequestSchema
    responses = ServiceApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateInternetGatewayApiResponseSchema
        }
    })
    response_schema = CreateInternetGatewayApiResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get('gateway')
        service_definition_id = inner_data.get('Nvl_GatewayType')
        account_id = inner_data.get('owner_id')
        name = 'InternetGateway-%s' % id_gen()

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiNetworkService.plugintype)

        # get gateway definition
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiNetworkGateway.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        # create service
        data['computeZone'] = parent_plugin.resource_uuid

        from beehive_service.controller import ServiceController
        serviceController: ServiceController = controller
        plugin: ApiNetworkGateway = serviceController.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=name,
                                                    parent_plugin=parent_plugin, instance_config=data)
        plugin.post_get()

        res = {
            'CreateInternetGatewayResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'internetGateway': {
                    'internetGatewayId': plugin.instance.uuid,
                    'attachmentSet': [],
                    'tagSet': []
                },
            }
        }
        self.logger.debug('Service Aws response: %s' % res)

        return res, 202


class DeleteInternetGatewayResponseItemSchema(Schema):
    requestId = fields.String(required=True, example='123eduis9', default='The ID of the request')
    nvl_return = fields.Boolean(required=True, example=True, data_key='return')


class DeleteInternetGatewayResponseSchema(Schema):
    DeleteInternetGatewayResponse = fields.Nested(DeleteInternetGatewayResponseItemSchema, required=True, many=False,
                                                  allow_none=False)


class DeleteInternetGatewayRequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', example='iu89-90sn',
                                      description='The ID of the internet gateway.')


class DeleteInternetGatewayBodyRequestSchema(Schema):
    body = fields.Nested(DeleteInternetGatewayRequestSchema, context='body')


class DeleteInternetGateway(ServiceApiView):
    summary = 'Terminate network gateway'
    description = 'Terminate network gateway'
    tags = ['networkservice']
    definitions = {
        'DeleteInternetGatewayRequestSchema': DeleteInternetGatewayRequestSchema,
        'DeleteInternetGatewayResponseSchema': DeleteInternetGatewayResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteInternetGatewayBodyRequestSchema)
    parameters_schema = DeleteInternetGatewayRequestSchema
    responses = SwaggerApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DeleteInternetGatewayResponseSchema
        }
    })
    response_schema = DeleteInternetGatewayResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        gateway_id = data.pop('InternetGatewayId')
        type_plugin = controller.get_service_type_plugin(gateway_id)
        type_plugin.delete()

        res = {
            'DeleteInternetGatewayResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'return': True
            }
        }

        return res, 202


class AttachInternetGateway1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', descritpion='request id')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='active task id')


class AttachInternetGatewayResponseSchema(Schema):
    AttachInternetGatewayResponse = fields.Nested(AttachInternetGateway1ResponseSchema, required=True, many=False,
                                                  allow_none=False)


class AttachInternetGateway1RequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', description='The ID of the gateway')
    VpcId = fields.String(required=True, context='query', description='The ID of the vpc')


class AttachInternetGatewayRequestSchema(Schema):
    gateway = fields.Nested(AttachInternetGateway1RequestSchema, context='body')


class AttachInternetGatewayBodyRequestSchema(Schema):
    body = fields.Nested(AttachInternetGatewayRequestSchema, context='body')


class AttachInternetGateway(ServiceApiView):
    summary = 'Attaches an internet gateway to a VPC'
    description = 'Attaches an internet gateway to a VPC'
    tags = ['networkservice']
    definitions = {
        'AttachInternetGatewayRequestSchema': AttachInternetGatewayRequestSchema,
        'AttachInternetGatewayResponseSchema': AttachInternetGatewayResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(AttachInternetGatewayBodyRequestSchema)
    parameters_schema = AttachInternetGatewayRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': AttachInternetGatewayResponseSchema
        }
    })
    response_schema = AttachInternetGatewayResponseSchema

    def put(self, controller, data, *args, **kwargs):
        data = data.get('gateway')
        gateway_id = data.pop('InternetGatewayId')
        vpc_id = data.pop('VpcId')
        type_plugin = controller.get_service_type_plugin(gateway_id)
        type_plugin.attach_vpc(vpc_id)

        res = {
            'AttachInternetGatewayResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class DetachInternetGateway1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', descritpion='request id')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='active task id')


class DetachInternetGatewayResponseSchema(Schema):
    DetachInternetGatewayResponse = fields.Nested(DetachInternetGateway1ResponseSchema, required=True, many=False,
                                                  allow_none=False)


class DetachInternetGateway1RequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', description='The ID of the gateway')
    VpcId = fields.String(required=True, context='query', description='The ID of the vpc')


class DetachInternetGatewayRequestSchema(Schema):
    gateway = fields.Nested(DetachInternetGateway1RequestSchema, context='body')


class DetachInternetGatewayBodyRequestSchema(Schema):
    body = fields.Nested(DetachInternetGatewayRequestSchema, context='body')


class DetachInternetGateway(ServiceApiView):
    summary = 'Detaches an internet gateway to a VPC'
    description = 'Detaches an internet gateway to a VPC'
    tags = ['networkservice']
    definitions = {
        'DetachInternetGatewayRequestSchema': DetachInternetGatewayRequestSchema,
        'DetachInternetGatewayResponseSchema': DetachInternetGatewayResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DetachInternetGatewayBodyRequestSchema)
    parameters_schema = DetachInternetGatewayRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': DetachInternetGatewayResponseSchema
        }
    })
    response_schema = DetachInternetGatewayResponseSchema

    def put(self, controller, data, *args, **kwargs):
        data = data.get('gateway')
        gateway_id = data.pop('InternetGatewayId')
        vpc_id = data.pop('VpcId')
        type_plugin = controller.get_service_type_plugin(gateway_id)
        type_plugin.detach_vpc(vpc_id)

        res = {
            'DetachInternetGatewayResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class DescribeInternetGatewayBastion2ResponseSchema(Schema):
    nvl_name = fields.String(required=False, example='test', descriptiom='gateway bastion name', data_key='nvl-name')
    nvl_state = fields.String(required=False, example='pending', data_key='nvl-state',
                              description='state of the gateway bastion')


class DescribeInternetGatewayBastion1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='ednundw83ldw', description='request id')
    internetGatewayBastion = fields.Nested(DescribeInternetGatewayBastion2ResponseSchema, many=True, required=True,
                                           description='internet gateway bastion')


class DescribeInternetGatewayBastionResponseSchema(Schema):
    DescribeInternetGatewayBastionResponse = fields.Nested(DescribeInternetGatewayBastion1ResponseSchema, required=True,
                                                           allow_none=False)


class DescribeInternetGatewayBastionRequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', description='Internet gateway IDs')


class DescribeInternetGatewayBastion(ServiceApiView):
    summary = 'Get an internet gateway bastion'
    description = 'Get an internet gateway bastion'
    tags = ['networkservice']
    definitions = {
        'DescribeInternetGatewayBastionRequestSchema': DescribeInternetGatewayBastionRequestSchema,
        'DescribeInternetGatewayBastionResponseSchema': DescribeInternetGatewayBastionResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DescribeInternetGatewayBastionRequestSchema)
    parameters_schema = DescribeInternetGatewayBastionRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': DescribeInternetGatewayBastionResponseSchema
        }
    })
    response_schema = DescribeInternetGatewayBastionResponseSchema

    def get(self, controller, data, *args, **kwargs):
        gateway_id = data.get('InternetGatewayId')
        type_plugin = controller.get_service_type_plugin(gateway_id)
        bastion = type_plugin.get_bastion()

        res = {
            'DescribeInternetGatewayBastionResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'internetGatewayBastion': bastion
            }
        }
        return res, 202


class CreateInternetGatewayBastion1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', descritpion='request id')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='active task id')


class CreateInternetGatewayBastionResponseSchema(Schema):
    CreateInternetGatewayBastionResponse = fields.Nested(CreateInternetGatewayBastion1ResponseSchema,
                                                         required=True, many=False, allow_none=False)


class CreateInternetGatewayBastion1RequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', description='The ID of the gateway')


class CreateInternetGatewayBastionRequestSchema(Schema):
    bastion = fields.Nested(CreateInternetGatewayBastion1RequestSchema, context='body')


class CreateInternetGatewayBastionBodyRequestSchema(Schema):
    body = fields.Nested(CreateInternetGatewayBastionRequestSchema, context='body')


class CreateInternetGatewayBastion(ServiceApiView):
    summary = 'Create an internet gateway bastion'
    description = 'Create an internet gateway bastion'
    tags = ['networkservice']
    definitions = {
        'CreateInternetGatewayBastionRequestSchema': CreateInternetGatewayBastionRequestSchema,
        'CreateInternetGatewayBastionResponseSchema': CreateInternetGatewayBastionResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateInternetGatewayBastionBodyRequestSchema)
    parameters_schema = CreateInternetGatewayBastionRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateInternetGatewayBastionResponseSchema
        }
    })
    response_schema = CreateInternetGatewayBastionResponseSchema

    def post(self, controller, data, *args, **kwargs):
        data = data.get('bastion')
        gateway_id = data.pop('InternetGatewayId')
        type_plugin: ApiNetworkGateway = controller.get_service_type_plugin(gateway_id)
        type_plugin.create_bastion()

        res = {
            'CreateInternetGatewayBastionResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class DeleteInternetGatewayBastion1ResponseSchema(Schema):
    requestId = fields.String(required=True, example='erc453', descritpion='request id')
    return_status = fields.Boolean(required=True, example=True, data_key='return',
                                   description='Is true if the request succeeds, and an error otherwise')
    nvl_activeTask = fields.String(required=True, allow_none=True, data_key='nvl-activeTask',
                                   description='active task id')


class DeleteInternetGatewayBastionResponseSchema(Schema):
    DeleteInternetGatewayBastionResponse = fields.Nested(DeleteInternetGatewayBastion1ResponseSchema,
                                                         required=True, many=False, allow_none=False)


class DeleteInternetGatewayBastion1RequestSchema(Schema):
    InternetGatewayId = fields.String(required=True, context='query', description='The ID of the gateway')


class DeleteInternetGatewayBastionRequestSchema(Schema):
    bastion = fields.Nested(DeleteInternetGatewayBastion1RequestSchema, context='body')


class DeleteInternetGatewayBastionBodyRequestSchema(Schema):
    body = fields.Nested(DeleteInternetGatewayBastionRequestSchema, context='body')


class DeleteInternetGatewayBastion(ServiceApiView):
    summary = 'Delete an internet gateway bastion'
    description = 'Delete an internet gateway bastion'
    tags = ['networkservice']
    definitions = {
        'DeleteInternetGatewayBastionRequestSchema': DeleteInternetGatewayBastionRequestSchema,
        'DeleteInternetGatewayBastionResponseSchema': DeleteInternetGatewayBastionResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteInternetGatewayBastionBodyRequestSchema)
    parameters_schema = DeleteInternetGatewayBastionRequestSchema
    responses = SwaggerApiView.setResponses({
        202: {
            'description': 'success',
            'schema': DeleteInternetGatewayBastionResponseSchema
        }
    })
    response_schema = DeleteInternetGatewayBastionResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        data = data.get('bastion')
        gateway_id = data.pop('InternetGatewayId')
        type_plugin = controller.get_service_type_plugin(gateway_id)
        type_plugin.delete_bastion()

        res = {
            'DeleteInternetGatewayBastionResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'nvl-activeTask': type_plugin.active_task,
                'return': True
            }
        }
        return res, 202


class NetworkGatewayAPI(ApiView):
    @staticmethod
    def register_api(module, rules=None, **kwargs):
        base = module.base_path + '/networkservices/gateway'
        rules = [
            ('%s/describeinternetgateways' % base, 'GET', DescribeInternetGateways, {}),
            ('%s/createinternetgateway' % base, 'POST', CreateInternetGateway, {}),
            ('%s/deleteinternetgateway' % base, 'DELETE', DeleteInternetGateway, {}),
            ('%s/attachinternetgateway' % base, 'PUT', AttachInternetGateway, {}),
            ('%s/detachinternetgateway' % base, 'PUT', DetachInternetGateway, {}),
            # ('%s/describeegressonlyinternetgateways' % base, 'GET', DescribeEgressonlyinternetgateways, {}),
            # ('%s/createegressonlyinternetgateway' % base, 'POST', CreateEgressonlyinternetgateway, {}),
            # ('%s/deleteegressonlyinternetgateway' % base, 'DELETE', DeleteEgressonlyinternetgateway, {}),

            ('%s/describinternetgatewayebastion' % base, 'GET', DescribeInternetGatewayBastion, {}),
            ('%s/createinternetgatewaybastion' % base, 'POST', CreateInternetGatewayBastion, {}),
            ('%s/deleteinternetgatewaybastion' % base, 'DELETE', DeleteInternetGatewayBastion, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
