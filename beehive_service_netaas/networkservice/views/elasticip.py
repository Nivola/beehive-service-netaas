# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from beehive_service.controller import ServiceController
from flasgger import Schema
from beehive.common.apimanager import ApiView
from beehive.common.data import operation
from beehive_service.model.base import SrvStatusType
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf

from beehive_service.plugins.computeservice.controller import (
    ApiComputeVPC,
    ApiComputeService,
)


class InstanceTagSetResponseSchema(Schema):
    key = fields.String(required=False, allow_none=True, metadata={"description": "tag key"})
    value = fields.String(required=False, allow_none=True, metadata={"description": "tag value"})


class ElasticIpIpv6CidrBlockAssociationResponseSchema(Schema):
    pass


class ElasticIpCidrBlockStateResponseSchema(Schema):
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


class ElasticIpCidrBlockAssociationResponseSchema(Schema):
    associationId = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "association ID for the IPv4 CIDR block"},
    )

    cidrBlock = fields.String(required=False, allow_none=True, metadata={"description": "IPv4 CIDR block"})
    cidrBlockState = fields.Nested(ElasticIpCidrBlockStateResponseSchema, many=False, required=False, allow_none=True)


class ElasticIpItemParameterResponseSchema(Schema):
    cidrBlock = fields.String(
        required=False,
        allow_none=True,
        metadata={"description": "primary IPv4 CIDR block for the VPC"},
    )

    cidrBlockAssociationSet = fields.Nested(
        ElasticIpCidrBlockAssociationResponseSchema,
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
        ElasticIpIpv6CidrBlockAssociationResponseSchema,
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

    #   validate=OneOf(['pending', 'available', 'transient', 'error']),
    tagSet = fields.Nested(InstanceTagSetResponseSchema, many=True, required=False, allow_none=True)
    vpcId = fields.String(required=False, allow_none=True, metadata={"example": "12", "description": "ID of the VPC"})

    nvl_name = fields.String(
        required=False, allow_none=True, data_key="nvl-name",
        metadata={"description": "service instance name"},
    )

    nvl_vpcName = fields.String(
        required=False, allow_none=True, data_key="nvl-vpcName",
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
        required=False, allow_none=True,
        metadata={"description": "ID of the account that owns the vpc"},
    )

    nvl_resourceId = fields.String(
        required=False,
        allow_none=True,
        data_key="nvl-resourceId",
        metadata={"description": "vpc resource id"},
    )


class DescribeAddressesResponse1Schema(Schema):
    requestId = fields.String(required=True, allow_none=True)
    vpcSet = fields.Nested(ElasticIpItemParameterResponseSchema, many=True, required=False, allow_none=True)


class DescribeAddressesResponseSchema(Schema):
    DescribeAddressesResponse = fields.Nested(
        DescribeAddressesResponse1Schema,
        required=True,
        many=False,
        allow_none=False,
    )


class DescribeAddressesRequestSchema(Schema):
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
    ElasticIpId_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="ElasticIpId.N",
        metadata={"description": "One or more VPC IDs"},
    )

    Nvl_MaxResults = fields.Integer(
        required=False,
        dump_default=10,
        data_key="Nvl-MaxResults",
        context="query",
        metadata={"description": ""},
    )

    Nvl_NextToken = fields.String(
        required=False,
        dump_default="0",
        data_key="Nvl-NextToken",
        context="query",
        metadata={"description": ""},
    )


class DescribeAddresses(ServiceApiView):
    summary = "Describe compute vpc"
    description = "Describe compute vpc"
    tags = ["computeservice"]
    definitions = {"DescribeAddressesResponseSchema": DescribeAddressesResponseSchema}
    parameters = SwaggerHelper().get_parameters(DescribeAddressesRequestSchema)
    parameters_schema = DescribeAddressesRequestSchema
    responses = ServiceApiView.setResponses(
        {200: {"description": "success", "schema": DescribeAddressesResponseSchema}}
    )

    def get(self, controller, data, *args, **kwargs):
        data_search = {}
        data_search["size"] = data.get("Nvl_MaxResults", 10)
        data_search["page"] = int(data.get("Nvl_NextToken", 0))

        # check Account
        account_id_list = data.get("owner_id_N", [])

        # get instance identifier
        instance_id_list = data.get("vpc_id_N", [])
        instance_id_list.extend(data.get("ElasticIpId_N", []))

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
            "DescribeAddressesResponse": {
                "$xmlns": self.xmlns,
                "requestId": operation.id,
                "vpcSet": instances_set,
                "nvl-vpcTotal": total,
            }
        }
        return res


class AllocateAddressApiResponse1Schema(Schema):
    groupId = fields.String(required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class AllocateAddressApiResponseSchema(Schema):
    AllocateAddressResponse = fields.Nested(AllocateAddressApiResponse1Schema, required=True, allow_none=False)


class AllocateAddressApiParamRequestSchema(Schema):
    owner_id = fields.String(required=True, data_key="owner_id", metadata={"description": "account id"})
    ElasticIpName = fields.String(required=True, metadata={"description": "name of the vpc"})
    ElasticIpDescription = fields.String(required=False, metadata={"description": "description of the vpc"})
    ElasticIpType = fields.String(required=False, load_default=None, metadata={"description": "vpc template"})

    CidrBlock = fields.String(
        required=False,
        load_default=None,
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


class AllocateAddressApiRequestSchema(Schema):
    vpc = fields.Nested(AllocateAddressApiParamRequestSchema, context="body")


class AllocateAddressApiBodyRequestSchema(Schema):
    body = fields.Nested(AllocateAddressApiRequestSchema, context="body")


class AllocateAddress(ServiceApiView):
    summary = "Create compute vpc"
    description = "Create compute vpc"
    tags = ["computeservice"]

    definitions = {
        "AllocateAddressApiRequestSchema": AllocateAddressApiRequestSchema,
        "AllocateAddressApiResponseSchema": AllocateAddressApiResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(AllocateAddressApiBodyRequestSchema)
    parameters_schema = AllocateAddressApiRequestSchema

    responses = ServiceApiView.setResponses(
        {202: {"description": "success", "schema": AllocateAddressApiResponseSchema}}
    )

    def post(self, controller: ServiceController, data, *args, **kwargs):
        inner_data = data.get("vpc")
        service_definition_id = inner_data.get("ElasticIpType")
        account_id = inner_data.get("owner_id")
        name = inner_data.get("ElasticIpName")
        desc = inner_data.get("ElasticIpDescription", name)

        # check instance with the same name already exists
        # self.service_exist(controller, name, ApiComputeInstance.plugintype)

        # check account
        account, parent_plugin = self.check_parent_service(
            controller, account_id, plugintype=ApiComputeService.plugintype
        )

        # get vpc definition
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiComputeVPC.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        # create service
        data["computeZone"] = parent_plugin.resource_uuid
        inst = controller.add_service_type_plugin(
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
            "AllocateAddressResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "vpc": inst.aws_info(),
            }
        }
        self.logger.debug("Service Aws response: %s" % res)

        return res, 202


class NetworkElasticIpAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/elasticip"
        rules = [
            ("%s/allocateaddress" % base, "POST", AllocateAddress, {}),
            ("%s/describeaddresses" % base, "GET", DescribeAddresses, {}),
            ##("%s/associateaddress" % base, "PUT", AssociateAddress, {}),
            ## ('%s/Describemovingaddresses' % base, 'GET', DescribeMovingAddresses, {}),
            ##("%s/Disassociateaddress" % base, "PUT", DisassociateAddress, {}),
            ## ('%s/moveaddresstovpc' % base, 'PUT', MoveAddressToVpc, {}),
            ##("%s/releaseaddress" % base, "DELETE", ReleaseAddress, {}),
            ## ('%s/restoreaddresstoclassic' % base, 'PUT', RestoreAddressToClassic, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
