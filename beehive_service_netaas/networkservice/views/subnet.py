# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2024 CSI-Piemonte

from flasgger import fields, Schema
from beehive.common.apimanager import ApiView
from beehive.common.data import operation
from beehive_service.model.base import SrvStatusType
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf
from beehive_service.controller import ApiServiceType
from beehive.common.assert_util import AssertUtil
from beehive_service.plugins.computeservice.controller import (
    ApiComputeVPC,
    ApiComputeSubnet,
    ApiComputeService,
)
from beecell.simple import merge_dicts
from beehive_service_netaas.networkservice.validation import validate_network


class InstanceTagSetResponseSchema(Schema):
    key = fields.String(required=False, description="tag key")
    value = fields.String(required=False, description="tag value")


class ipv6CidrBlockStateResponseSchema(Schema):
    state = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="state of the CIDR block",
    )
    statusMessage = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="state of the CIDR block",
        validate=OneOf(
            [
                "associating",
                "associated",
                "disassociating",
                "disassociated",
                "failing",
                "failed",
            ]
        ),
    )


class ipv6CidrBlockAssociationResponseSchema(Schema):
    associationId = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="association ID for the IPv4 CIDR block",
    )
    ipv6CidrBlock = fields.String(required=False, allow_none=True, example="", description="IPv6 CIDR block")
    ipv6CidrBlockState = fields.Nested(ipv6CidrBlockStateResponseSchema, many=True, required=False, allow_none=True)


class SubnetItemParameterResponseSchema(Schema):
    assignIpv6AddressOnCreation = fields.Boolean(required=False, default=False)
    availabilityZone = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="Availability Zone of the subnet.",
    )
    availableIpAddressCount = fields.Integer(required=False, allow_none=True)
    cidrBlock = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="primary IPv4 CIDR block for the subnet",
    )
    defaultForAz = fields.Boolean(required=False, default=True)
    ipv6CidrBlockAssociationSet = fields.Nested(
        ipv6CidrBlockAssociationResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        description="IPv6 CIDR blocks associated with the subnet",
    )
    mapPublicIpOnLaunch = fields.Boolean(required=False, default=True)
    state = fields.String(
        required=False,
        allow_none=True,
        example="pending",
        description="state of the VPC (pending | available | transient | error)",
        validate=OneOf(
            [
                getattr(ApiComputeSubnet.state_enum, x)
                for x in dir(ApiComputeSubnet.state_enum)
                if not x.startswith("__")
            ]
        ),
    )
    tagSet = fields.Nested(
        InstanceTagSetResponseSchema,
        many=True,
        required=False,
        allow_none=True,
    )
    subnetId = fields.String(required=False, allow_none=True, example="12", descriptiom="ID of the Subnet")
    vpcId = fields.String(required=False, allow_none=True, example="12", descriptiom="ID of the VPC")
    nvl_name = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="service instance name",
        data_key="nvl-name",
    )
    nvl_vpcName = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="vpc name",
        data_key="nvl-vpcName",
    )
    nvl_subnetOwnerId = fields.String(
        required=False,
        allow_none=True,
        example="",
        data_key="nvl-subnetOwnerId",
        description="ID of the account that owns the subnet",
    )
    nvl_subnetOwnerAlias = fields.String(
        required=False,
        allow_none=True,
        example="",
        data_key="nvl-subnetOwnerAlias",
        description="alias of the account that owns the subnet",
    )
    ownerId = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="ID of the account that owns the subnet",
    )


class DescribeSubnetsResponse1Schema(Schema):
    requestId = fields.String(required=True, example="", description="")
    subnetSet = fields.Nested(SubnetItemParameterResponseSchema, required=True, many=True, allow_none=False)
    nvl_subnetTotal = fields.Integer(
        required=True,
        example="",
        description="total number of subnet",
        data_key="nvl-subnetTotal",
    )
    xmlns = fields.String(required=False, data_key="$xmlns")


class DescribeSubnetsResponseSchema(Schema):
    DescribeSubnetsResponse = fields.Nested(DescribeSubnetsResponse1Schema, required=True, many=False, allow_none=False)


class DescribeSubnetsRequestSchema(Schema):
    owner_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="owner-id.N",
        description="account ID of the image owner",
    )
    # availabilityZone_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                  context='query', collection_format='multi', data_key='availabilityZone.N',
    #                                  descriptiom='Availability Zone for the subnet')
    state_N = fields.List(
        fields.String(example="", validate=OneOf(["pending", "available"])),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="state.N",
        descriptiom="state of the VPC (pending | available)",
    )
    tag_key_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="tag-key.N",
        descriptiom="value of a tag assigned to the resource",
    )
    subnet_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="subnet-id.N",
        descriptiom=" ID of the subnet",
    )
    SubnetId_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="SubnetId.N",
        description=" ID of the subnet",
    )
    vpc_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="vpc-id.N",
        descriptiom="ID of the VPC",
    )
    # cidrBlock_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                           context='query', collection_format='multi', data_key='cidrBlock.N',
    #                           descriptiom='primary IPv4 CIDR block of the resource')
    Nvl_MaxResults = fields.Integer(
        required=False,
        default=10,
        description="",
        data_key="Nvl-MaxResults",
        context="query",
    )
    Nvl_NextToken = fields.String(
        required=False,
        default="0",
        description="",
        data_key="Nvl-NextToken",
        context="query",
    )


class DescribeSubnets(ServiceApiView):
    summary = "Describe compute subnet"
    description = "Describe compute subnet"
    tags = ["computeservice"]
    definitions = {"DescribeSubnetsResponseSchema": DescribeSubnetsResponseSchema}
    parameters = SwaggerHelper().get_parameters(DescribeSubnetsRequestSchema)
    parameters_schema = DescribeSubnetsRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": DescribeSubnetsResponseSchema}})
    response_schema = DescribeSubnetsResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {}
        data_search["size"] = data.get("Nvl_MaxResults", 10)
        data_search["page"] = int(data.get("Nvl_NextToken", 0))

        # check Account
        account_id_list = data.get("owner_id_N", [])

        # get instance identifier
        instance_id_list = data.get("subnet_id_N", [])
        instance_id_list.extend(data.get("SubnetId_N", []))

        # get vpc
        vpc_ids = data.get("vpc_id_N", [])
        for vpc_id in vpc_ids:
            vpc_srv = controller.get_service_type_plugin(vpc_id, plugin_class=ApiComputeVPC)
            vpc_subnet_srvs = vpc_srv.get_child_type_plugin_instances(plugin_class=ApiComputeSubnet)
            for subnet in vpc_subnet_srvs:
                if subnet.instance.uuid not in instance_id_list:
                    instance_id_list.append(subnet.instance.uuid)

        # get tags
        tag_values = data.get("tag_key_N", None)
        # resource_tags = ['nws$%s' % t for t in tag_values]

        # get status
        status_mapping = {
            "pending": SrvStatusType.PENDING,
            "available": SrvStatusType.ACTIVE,
        }

        status_name_list = None
        status_list = data.get("state_N", None)
        if status_list is not None:
            status_name_list = [status_mapping[i] for i in status_list if i in status_mapping.keys()]

        # get instances list
        res, total = controller.get_service_type_plugins(
            service_uuid_list=instance_id_list,
            account_id_list=account_id_list,
            servicetags_or=tag_values,
            service_status_name_list=status_name_list,
            plugintype=ApiComputeSubnet.plugintype,
            **data_search,
        )

        # format result
        instances_set = [r.aws_info() for r in res]

        res = {
            "DescribeSubnetsResponse": {
                "$xmlns": self.xmlns,
                "requestId": operation.id,
                "subnetSet": instances_set,
                "nvl-subnetTotal": total,
            }
        }
        return res


class CreateSubnetApiResponse1Schema(Schema):
    groupId = fields.String(required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class CreateSubnetApiResponseSchema(Schema):
    CreateSubnetResponse = fields.Nested(CreateSubnetApiResponse1Schema, required=True, allow_none=False)


class CreateSubnetApiParamRequestSchema(Schema):
    SubnetName = fields.String(required=True, example="", description="name of the subnet")
    SubnetDescription = fields.String(required=False, example="", description="description of the subnet")
    VpcId = fields.String(required=True, example="", description="parent vpc id or uuid")
    AvailabilityZone = fields.String(required=True, example="", description="subnet availability zone")
    CidrBlock = fields.String(
        required=True, example="", validate=validate_network, description="subnet cidr like ###.###.###.###/##"
    )
    Nvl_SubnetType = fields.String(required=False, missing=None, description="subnet template")


class CreateSubnetApiRequestSchema(Schema):
    subnet = fields.Nested(CreateSubnetApiParamRequestSchema, context="body")


class CreateSubnetApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateSubnetApiRequestSchema, context="body")


class CreateSubnet(ServiceApiView):
    summary = "Create a compute subnet"
    description = "Create a compute subnet"
    tags = ["computeservice"]
    definitions = {
        "CreateSubnetApiRequestSchema": CreateSubnetApiRequestSchema,
        "CreateSubnetApiResponseSchema": CreateSubnetApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSubnetApiBodyRequestSchema)
    parameters_schema = CreateSubnetApiRequestSchema
    responses = ServiceApiView.setResponses({202: {"description": "success", "schema": CreateSubnetApiResponseSchema}})
    response_schema = CreateSubnetApiResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get("subnet")
        service_definition_id = inner_data.get("Nvl_SubnetType")
        name = inner_data.get("SubnetName")
        desc = inner_data.get("SubnetDescription", name)
        vpc_id = inner_data.get("VpcId")

        # get vpc service
        inst_vpc = controller.get_service_type_plugin(vpc_id, plugin_class=ApiComputeVPC, details=False)
        account_id = inst_vpc.instance.account_id

        # check account
        account, parent_plugin = self.check_parent_service(
            controller, account_id, plugintype=ApiComputeService.plugintype
        )

        # get subnet definition
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiComputeSubnet.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        data["computeZone"] = parent_plugin.resource_uuid
        inst = controller.add_service_type_plugin(
            service_definition.oid,
            account_id,
            name=name,
            desc=desc,
            parent_plugin=inst_vpc,
            instance_config=data,
        )
        inst.post_get()

        res = {
            "CreateSubnetResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "subnet": inst.aws_info(),
            }
        }
        self.logger.debug("Service Aws response: %s" % res)

        return res, 202


class NetworkSubnetAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/vpc"
        rules = [
            ("%s/describesubnets" % base, "GET", DescribeSubnets, {}),
            ("%s/createsubnet" % base, "POST", CreateSubnet, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
