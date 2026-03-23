# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte
from beehive_service.controller import ServiceController, ApiServiceDefinition
from flasgger import Schema, fields
from beehive.common.apimanager import ApiView, ApiManagerError
from beehive.common.data import operation
from beehive_service.model.base import SrvStatusType
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper

# from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf
from beehive_service.plugins.computeservice.controller import (
    ApiComputeVPC,
    ApiComputeService,
)
from beehive_service_netaas.networkservice.validation import validate_network


class InstanceTagSetResponseSchema(Schema):
    key = fields.String(required=False, allow_none=True, metadata={"description": "tag key"})
    value = fields.String(required=False, allow_none=True, metadata={"description": "tag value"})


class VpcIpv6CidrBlockAssociationResponseSchema(Schema):
    pass


class VpcCidrBlockStateResponseSchema(Schema):
    state = fields.String(
        required=False,
        allow_none=True,
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
        metadata={"description": "state of the CIDR block"},
    )
    statusMessage = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "message about the status of the CIDR block"},
    )


class VpcCidrBlockAssociationResponseSchema(Schema):
    associationId = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "association ID for the IPv4 CIDR block"},
    )
    cidrBlock = fields.String(required=False, allow_none=True, metadata={"description": "IPv4 CIDR block"})
    cidrBlockState = fields.Nested(VpcCidrBlockStateResponseSchema, many=False, required=False, allow_none=True)


class VpcItemParameterResponseSchema(Schema):
    cidrBlock = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "primary IPv4 CIDR block for the VPC"},
    )

    cidrBlockAssociationSet = fields.Nested(
        VpcCidrBlockAssociationResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        metadata={"description": "IPv4 CIDR blocks associated with the VPC"},
    )

    dhcpOptionsId = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "ID of the set of DHCP options associated with VPC"},
    )

    instanceTenancy = fields.String(
        required=False,
        allow_none=True,
        validate=OneOf(["default", "dedicated", "host"]),
        metadata={"description": "allowed tenancy of instances launched into the VPC"},
    )

    ipv6CidrBlockAssociationSet = fields.Nested(
        VpcIpv6CidrBlockAssociationResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        metadata={"description": "IPv6 CIDR blocks associated with the VPC"},
    )

    isDefault = fields.Boolean(required=None, metadata={"description": "Indicates whether the VPC is the default VPC"})

    state = fields.String(
        required=False,
        allow_none=True,
        validate=OneOf(
            [getattr(ApiComputeVPC.state_enum, x) for x in dir(ApiComputeVPC.state_enum) if not x.startswith("__")]
        ),
        metadata={"example": "pending", "description": "state of the VPC (pending | available | transient | error)"},
    )

    tagSet = fields.Nested(InstanceTagSetResponseSchema, many=True, required=False, allow_none=True)
    vpcId = fields.String(required=False, allow_none=True, metadata={"example": "12", "description": "ID of the VPC"})

    nvl_name = fields.String(
        required=False,
        allow_none=True,
        data_key="nvl-name",
        metadata={"description": "service instance name"},
    )

    nvl_vpcName = fields.String(
        required=False,
        allow_none=True,
        data_key="nvl-vpcName",
        metadata={"description": "vpc name"},
    )

    nvl_vpcOwnerId = fields.String(
        required=False,
        allow_none=True,
        data_key="nvl-vpcOwnerId",
        metadata={"description": "Id of the account that owns the VPC"},
    )

    nvl_vpcOwnerAlias = fields.String(
        required=False,
        allow_none=True,
        data_key="nvl-vpcOwnerAlias",
        metadata={"description": "alias of the account that owns the VPC"},
    )

    ownerId = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "ID of the account that owns the vpc"},
    )

    nvl_resourceId = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "vpc resource id"},
        data_key="nvl-resourceId",
    )


class DescribeVpcsResponse1Schema(Schema):
    requestId = fields.String(required=True, allow_none=True, metadata={"description": ""})
    vpcSet = fields.Nested(VpcItemParameterResponseSchema, many=True, required=False, allow_none=True)
    xmlns = fields.String(required=False, data_key="$xmlns")
    nvl_vpcTotal = fields.Integer(
        required=True,
        data_key="nvl-vpcTotal",
        metadata={"description": "total number of vpc"},
    )


class DescribeVpcsResponseSchema(Schema):
    DescribeVpcsResponse = fields.Nested(DescribeVpcsResponse1Schema, required=True, many=False, allow_none=False)


class DescribeVpcsRequestSchema(Schema):
    owner_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="owner-id.N",
        metadata={"description": "account ID of the vpc owner"},
    )
    state_N = fields.List(
        fields.String(example="", validate=OneOf(["pending", "available"])),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="state.N",
        metadata={"description": "state of the VPC (pending | available)"},
    )
    tag_value_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="tag-value.N",
        metadata={"description": "value of a tag assigned to the resource"},
    )
    vpc_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="vpc-id.N",
        metadata={"description": "ID of the VPC"},
    )
    VpcId_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="VpcId.N",
        metadata={"description": "One or more VPC IDs"},
    )
    Nvl_MaxResults = fields.Integer(
        required=False,
        dump_default=10,
        data_key="Nvl-MaxResults",
        context="query",
    )
    Nvl_NextToken = fields.String(
        required=False,
        dump_default="0",
        data_key="Nvl-NextToken",
        context="query",
    )


class DescribeVpcs(ServiceApiView):
    summary = "Describe compute vpc"
    description = "Describe compute vpc"
    tags = ["computeservice"]
    definitions = {"DescribeVpcsResponseSchema": DescribeVpcsResponseSchema}
    parameters = SwaggerHelper().get_parameters(DescribeVpcsRequestSchema)
    parameters_schema = DescribeVpcsRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": DescribeVpcsResponseSchema}})
    response_schema = DescribeVpcsResponseSchema

    def get(self, controller: ServiceController, data, *args, **kwargs):
        data_search = {}
        data_search["size"] = data.get("Nvl_MaxResults", 10)
        data_search["page"] = int(data.get("Nvl_NextToken", 0))

        # check Account
        account_id_list = data.get("owner_id_N", [])

        # get instance identifier
        instance_id_list = data.get("vpc_id_N", [])
        instance_id_list.extend(data.get("VpcId_N", []))

        # get status
        status_mapping = {
            "pending": SrvStatusType.PENDING,
            "available": SrvStatusType.ACTIVE,
        }

        status_name_list = None
        status_list = data.get("state_N", None)
        if status_list is not None:
            status_name_list = [status_mapping[i] for i in status_list if i in status_mapping.keys()]

        # get tags
        tag_values = data.get("tag_value_N", None)

        # get instances list
        res, total = controller.get_service_type_plugins(
            service_uuid_list=instance_id_list,
            account_id_list=account_id_list,
            servicetags_or=tag_values,
            service_status_name_list=status_name_list,
            plugintype=ApiComputeVPC.plugintype,
            **data_search,
        )

        # format result
        instances_set = [r.aws_info() for r in res]

        res = {
            "DescribeVpcsResponse": {
                "$xmlns": self.xmlns,
                "requestId": operation.id,
                "vpcSet": instances_set,
                "nvl-vpcTotal": total,
            }
        }
        return res


class CreateVpcApiResponse1Schema(Schema):
    vpc = fields.Nested(VpcItemParameterResponseSchema, required=True, many=False, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)
    xmlns = fields.String(required=False, allow_none=True, data_key="__xmlns")

class CreateVpcApiResponseSchema(Schema):
    CreateVpcResponse = fields.Nested(CreateVpcApiResponse1Schema, required=True, allow_none=False)


class CreateVpcApiParamRequestSchema(Schema):
    owner_id = fields.String(required=True, data_key="owner_id", metadata={"description": "account id"})
    VpcName = fields.String(required=True, metadata={"description": "name of the vpc"})
    VpcDescription = fields.String(required=False, metadata={"description": "description of the vpc"})
    VpcType = fields.String(required=False, load_default=None, metadata={"description": "vpc template"})
    CidrBlock = fields.String(
        required=False,
        load_default=None,
        validate=validate_network,
        metadata={"example": "###.###.###.###/##", "description": "base vpc cidr block"},
    )
    InstanceTenancy = fields.String(
        required=False,
        allow_none=True,
        load_default="default",
        validate=OneOf(["default", "dedicated"]),
        metadata={"example": "default", "description": "allowed tenancy of instances launched into the VPC. Use default for "
        "shared vpc. Use dedicated for private vpc"},
    )


class CreateVpcApiRequestSchema(Schema):
    vpc = fields.Nested(CreateVpcApiParamRequestSchema, context="body")


class CreateVpcApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateVpcApiRequestSchema, context="body")


class CreateVpc(ServiceApiView):
    summary = "Create compute vpc"
    description = "Create compute vpc"
    tags = ["computeservice"]
    definitions = {
        "CreateVpcApiRequestSchema": CreateVpcApiRequestSchema,
        "CreateVpcApiResponseSchema": CreateVpcApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateVpcApiBodyRequestSchema)
    parameters_schema = CreateVpcApiRequestSchema
    responses = ServiceApiView.setResponses({202: {"description": "success", "schema": CreateVpcApiResponseSchema}})
    response_schema = CreateVpcApiResponseSchema

    def post(self, controller: ServiceController, data, *args, **kwargs):
        inner_data = data.get("vpc")
        service_definition_id = inner_data.get("VpcType")
        account_id = inner_data.get("owner_id")
        name = inner_data.get("VpcName")
        desc = inner_data.get("VpcDescription", name)

        # check instance with the same name already exists
        # self.service_exist(controller, name, ApiComputeInstance.plugintype)

        # check account
        account, parent_plugin = self.check_parent_service(
            controller, account_id, plugintype=ApiComputeService.plugintype
        )
        service_definition: ApiServiceDefinition
        # get vpc definition
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiComputeVPC.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        # TODO CHECK Account has definition
        ok, desc = account.can_instantiate(service_definition)
        if not ok:
            raise ApiManagerError(
                f" {desc}: account {account.name} cannot use definition {service_definition.name}", code=400
            )

        # create service
        data["computeZone"] = parent_plugin.resource_uuid
        inst: ApiComputeVPC = controller.add_service_type_plugin(
            service_definition.oid,
            account_id,
            name=name,
            desc=desc,
            parent_plugin=parent_plugin,
            instance_config=data,
            account=account,
        )
        inst.post_get()

        res = {
            "CreateVpcResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "vpc": inst.aws_info(),
            }
        }
        self.logger.debug("Service Aws response: %s" % res)

        return res, 202


class NetworkVpcAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/vpc"
        rules = [
            ("%s/describevpcs" % base, "GET", DescribeVpcs, {}),
            ("%s/createvpc" % base, "POST", CreateVpc, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
