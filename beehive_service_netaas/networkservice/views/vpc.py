# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte

from beehive_service.controller import ServiceController
from flasgger import Schema
from beehive.common.apimanager import ApiView
from beehive.common.data import operation
from beehive_service.model.base import SrvStatusType
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf
from beehive_service.plugins.computeservice.controller import ApiComputeVPC, ApiComputeService


class InstanceTagSetResponseSchema(Schema):
    key = fields.String(required=False, allow_none=True, description='tag key')
    value = fields.String(required=False, allow_none=True, description='tag value')


class VpcIpv6CidrBlockAssociationResponseSchema(Schema):
    pass


class VpcCidrBlockStateResponseSchema(Schema):
    state = fields.String(required=False, allow_none=True, example='', description='state of the CIDR block',
                          validate=OneOf(['associating', 'associated', 'disassociating', 'disassociated', 'failing',
                                          'failed']))
    statusMessage = fields.String(required=False, allow_none=True, example='',
                                  description='message about the status of the CIDR block')


class VpcCidrBlockAssociationResponseSchema(Schema):
    associationId = fields.String(required=False, allow_none=True, example='',
                                  description='association ID for the IPv4 CIDR block')
    cidrBlock = fields.String(required=False, allow_none=True, example='', description='IPv4 CIDR block')
    cidrBlockState = fields.Nested(VpcCidrBlockStateResponseSchema, many=False, required=False, allow_none=True)


class VpcItemParameterResponseSchema(Schema):
    cidrBlock = fields.String(
        required=False,
        allow_none=True,
        example='',
        description='primary IPv4 CIDR block for the VPC')
    cidrBlockAssociationSet = fields.Nested(
        VpcCidrBlockAssociationResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        description='IPv4 CIDR blocks associated with the VPC')
    dhcpOptionsId = fields.String(
        required=False,
        allow_none=True,
        example='',
        description='ID of the set of DHCP options associated with VPC')
    instanceTenancy = fields.String(
        required=False, allow_none=True,
        example='',
        description='allowed tenancy of instances launched into the VPC',
        validate=OneOf(['default', 'dedicated', 'host']))
    ipv6CidrBlockAssociationSet = fields.Nested(
        VpcIpv6CidrBlockAssociationResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        description='IPv6 CIDR blocks associated with the VPC')
    isDefault = fields.Boolean(
        required=None,
        description='Indicates whether the VPC is the default VPC')
    state = fields.String(
        required=False,
        allow_none=True,
        example='pending',
        description='state of the VPC (pending | available | transient | error)',
        validate=OneOf([getattr(ApiComputeVPC.state_enum, x) for x in dir(ApiComputeVPC.state_enum) if not x.startswith("__")]))
    #   validate=OneOf(['pending', 'available', 'transient', 'error']),
    tagSet = fields.Nested(InstanceTagSetResponseSchema,
                           many=True, required=False, allow_none=True)
    vpcId = fields.String(
        required=False,
        allow_none=True,
        example='12',
        description='ID of the VPC')

    nvl_name = fields.String(
        required=False,
        allow_none=True,
        example='', descriptiom='service instance name',
        data_key='nvl-name')
    nvl_vpcName = fields.String(
        required=False,
        allow_none=True,
        example='',
        descriptiom='vpc name',
        data_key='nvl-vpcName')
    nvl_vpcOwnerId = fields.String(
        required=False,
        allow_none=True,
        example='',
        descriptiom='Id of the account that owns the VPC',
        data_key='nvl-vpcOwnerId')
    nvl_vpcOwnerAlias = fields.String(
        required=False,
        allow_none=True,
        example='',
        data_key='nvl-vpcOwnerAlias',
        descriptiom='alias of the account that owns the VPC')
    ownerId = fields.String(
        required=False,
        allow_none=True,
        example='',
        descriptiom='ID of the account that owns the vpc')

    nvl_resourceId = fields.String(
        required=False,
        allow_none=True,
        example='',
        descriptiom='vpc resource id',
        data_key='nvl-resourceId')


class DescribeVpcsResponse1Schema(Schema):
    requestId = fields.String(required=True, allow_none=True,  example='', description='')
    vpcSet = fields.Nested(VpcItemParameterResponseSchema, many=True, required=False, allow_none=True)
    xmlns = fields.String(required=False, data_key='$xmlns')
    nvl_vpcTotal = fields.Integer(required=True, description='total number of vpc', data_key='nvl-vpcTotal')


class DescribeVpcsResponseSchema(Schema):
    DescribeVpcsResponse = fields.Nested(DescribeVpcsResponse1Schema, required=True, many=False, allow_none=False)


class DescribeVpcsRequestSchema(Schema):
    owner_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
                             context='query', collection_format='multi', data_key='owner-id.N',
                             description='account ID of the vpc owner')
    # cidr_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                      context='query', collection_format='multi', data_key='cidr.N',
    #                      description='primary IPv4 CIDR block of the VPC')
    # cidr_block_association_cidr_block_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                   context='query', collection_format='multi',
    #                                                   data_key='cidr-block-association.cidr-block.N',
    #                                                   description='IPv4 CIDR block associated with the VPC')
    # cidr_block_association_association_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                       context='query', collection_format='multi',
    #                                                       data_key='cidr-block-association.cidr-block.N',
    #                                                       descriptiom='association ID for an IPv4 CIDR block '
    #                                                                   'associated with the VPC')
    # cidr_block_association_state_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                              context='query', collection_format='multi',
    #                                              data_key='cidr-block-association.state.N',
    #                                              descriptiom='state of an IPv4 CIDR block associated with the VPC')
    # dhcp_options_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                 context='query', collection_format='multi', data_key='dhcp-options-id.N',
    #                                 description='ID of a set of DHCP options')
    # ipv6_cidr_block_association_ipv6_cidr_block_N = fields.List(fields.String(example=''), required=False,
    #                                                             allow_none=True, context='query',
    #                                                             collection_format='multi',
    #                                                             data_key='ipv6-cidr-block-association.ipv6-'
    #                                                                       'cidr-block.N',
    #                                                             descriptiom='IPv6 CIDR block associated with the VPC')
    # ipv6_cidr_block_association_association_id_N = fields.List(fields.String(example=''), required=False,
    #                                                            allow_none=True, context='query',
    #                                                            collection_format='multi',
    #                                                            data_key='ipv6-cidr-block-association.'
    #                                                                      'association-id.N',
    #                                                            descriptiom='association ID for an IPv6 CIDR block '
    #                                                                        'associated with the VPC')
    # ipv6_cidr_block_association_state_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                   context='query', collection_format='multi',
    #                                                   data_key='ipv6-cidr-block-association.state.N',
    #                                                   descriptiom='state of an IPv6 CIDR block associated with '
    #                                                               'the VPC.')
    # isDefault_N = fields.List(fields.String(example=''), required=False, allow_none=True, context='query',
    #                           collection_format='multi', data_key='isDefault.N',
    #                           description='Indicates whether the VPC is the default VPC.')
    state_N = fields.List(fields.String(example='', validate=OneOf(['pending', 'available'])), required=False,
                          allow_none=True, context='query', collection_format='multi', data_key='state.N',
                          descriptiom='state of the VPC (pending | available)')
    tag_value_N = fields.List(fields.String(example=''), required=False, allow_none=True, context='query',
                              collection_format='multi', data_key='tag-value.N',
                              description='value of a tag assigned to the resource')
    vpc_id_N = fields.List(fields.String(example=''), required=False, allow_none=True, context='query',
                           collection_format='multi', data_key='vpc-id.N', description='ID of the VPC')
    VpcId_N = fields.List(fields.String(example=''), required=False, allow_none=False, context='query',
                          collection_format='multi', data_key='VpcId.N', description='One or more VPC IDs')
    Nvl_MaxResults = fields.Integer(required=False, default=10, description='', data_key='Nvl-MaxResults',
                                    context='query')
    Nvl_NextToken = fields.String(required=False, default='0', description='', data_key='Nvl-NextToken',
                                  context='query')


class DescribeVpcs(ServiceApiView):
    summary = 'Describe compute vpc'
    description = 'Describe compute vpc'
    tags = ['computeservice']
    definitions = {
        'DescribeVpcsResponseSchema': DescribeVpcsResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(DescribeVpcsRequestSchema)
    parameters_schema = DescribeVpcsRequestSchema
    responses = ServiceApiView.setResponses({
        200: {
            'description': 'success',
            'schema': DescribeVpcsResponseSchema
        }
    })
    response_schema = DescribeVpcsResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {}
        data_search['size'] = data.get('Nvl_MaxResults', 10)
        data_search['page'] = int(data.get('Nvl_NextToken', 0))

        # check Account
        account_id_list = data.get('owner_id_N', [])

        # get instance identifier
        instance_id_list = data.get('vpc_id_N', [])
        instance_id_list.extend(data.get('VpcId_N', []))

        # get status
        status_mapping = {
            'pending': SrvStatusType.PENDING,
            'available': SrvStatusType.ACTIVE,
        }

        status_name_list = None
        status_list = data.get('state_N', None)
        if status_list is not None:
            status_name_list = [status_mapping[i] for i in status_list if i in status_mapping.keys()]

        # get tags
        tag_values = data.get('tag_value_N', None)

        # get instances list
        res, total = controller.get_service_type_plugins(service_uuid_list=instance_id_list,
                                                         account_id_list=account_id_list,
                                                         servicetags_or=tag_values,
                                                         service_status_name_list=status_name_list,
                                                         plugintype=ApiComputeVPC.plugintype,
                                                         **data_search)

        # format result
        instances_set = [r.aws_info() for r in res]

        res = {
            'DescribeVpcsResponse': {
                '$xmlns': self.xmlns,
                'requestId': operation.id,
                'vpcSet': instances_set,
                'nvl-vpcTotal': total
            }
        }
        return res


class CreateVpcApiResponse1Schema(Schema):
    groupId = fields.String(required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class CreateVpcApiResponseSchema(Schema):
    CreateVpcResponse = fields.Nested(CreateVpcApiResponse1Schema, required=True, allow_none=False)


class CreateVpcApiParamRequestSchema(Schema):
    owner_id = fields.String(required=True, example='', description='account id', data_key='owner_id')
    VpcName = fields.String(required=True, example='', description='name of the vpc')
    VpcDescription = fields.String(required=False, example='', description='description of the vpc')
    VpcType = fields.String(required=False, missing=None, description='vpc template')
    CidrBlock = fields.String(required=False, example='10.0.0.0/16', missing=None, description='base vpc cidr block')
    InstanceTenancy = fields.String(required=False, allow_none=True, example='default', missing='default',
                                    description='allowed tenancy of instances launched into the VPC. Use default for '
                                                'shared vpc. Use dedicated for private vpc',
                                    validate=OneOf(['default', 'dedicated']))


class CreateVpcApiRequestSchema(Schema):
    vpc = fields.Nested(CreateVpcApiParamRequestSchema, context='body')


class CreateVpcApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateVpcApiRequestSchema, context='body')


class CreateVpc(ServiceApiView):
    summary = 'Create compute vpc'
    description = 'Create compute vpc'
    tags = ['computeservice']
    definitions = {
        'CreateVpcApiRequestSchema': CreateVpcApiRequestSchema,
        'CreateVpcApiResponseSchema': CreateVpcApiResponseSchema
    }
    parameters = SwaggerHelper().get_parameters(CreateVpcApiBodyRequestSchema)
    parameters_schema = CreateVpcApiRequestSchema
    responses = ServiceApiView.setResponses({
        202: {
            'description': 'success',
            'schema': CreateVpcApiResponseSchema
        }
    })
    response_schema = CreateVpcApiResponseSchema

    def post(self, controller: ServiceController, data, *args, **kwargs):
        inner_data = data.get('vpc')
        service_definition_id = inner_data.get('VpcType')
        account_id = inner_data.get('owner_id')
        name = inner_data.get('VpcName')
        desc = inner_data.get('VpcDescription', name)

        # check instance with the same name already exists
        # self.service_exist(controller, name, ApiComputeInstance.plugintype)

        # check account
        account, parent_plugin = self.check_parent_service(controller, account_id,
                                                           plugintype=ApiComputeService.plugintype)

        # get vpc definition
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiComputeVPC.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        # create service
        data['computeZone'] = parent_plugin.resource_uuid
        inst = controller.add_service_type_plugin(service_definition.oid, account_id, name=name, desc=desc,
                                                  parent_plugin=parent_plugin, instance_config=data, account=account)
        inst.post_get()

        res = {
            'CreateVpcResponse': {
                '__xmlns': self.xmlns,
                'requestId': operation.id,
                'vpc': inst.aws_info()
            }
        }
        self.logger.debug('Service Aws response: %s' % res)

        return res, 202


class NetworkVpcAPI(ApiView):
    @staticmethod
    def register_api(module, rules=None, **kwargs):
        base = module.base_path + '/networkservices/vpc'
        rules = [
            ('%s/describevpcs' % base, 'GET', DescribeVpcs, {}),
            ('%s/createvpc' % base, 'POST', CreateVpc, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
