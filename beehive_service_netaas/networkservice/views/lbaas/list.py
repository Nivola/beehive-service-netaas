# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte
#
# List LBAAS
#

from beehive.common.data import operation
from beehive_service.controller import ServiceController
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger import fields, Schema
from beehive_service_netaas.networkservice.controller.network_lbaas import (
    ApiNetworkLbaasInstance,
    LbaasInstanceInfoDict,
)
from .schemacommons import SwaggerTAG
from typing import TYPE_CHECKING, TypedDict, List


#
# Request
#
class ListLbaasRequestSchema(Schema):
    owner_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="owner-id.N",
        metadata={"description": "account ID of the lbaas owner"},
    )

    LbInstanceId_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="LbInstanceId.N",
        metadata={"description": "One or more internet lbaas IDs"},
    )

    LbInstanceName_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="LbInstanceName.N",
        metadata={"description": "One or more internet lbaas names"},
    )

    MaxResults = fields.Integer(
        required=False,
        dump_default=10,
        data_key="MaxResults",
        context="query",
    )

    NextToken = fields.String(
        required=False,
        dump_default="0",
        data_key="Nvl-NextToken",
        context="query",
    )


#
# Response
#
class ListLbaasRequestDict(TypedDict):
    owner_id_N: List[str]
    LbInstanceId_N: List[str]
    LbInstanceName_N: List[str]
    MaxResults: int
    NextToken: str


class LbaasInstanceInfoSchema(Schema):
    ownerId = fields.String(required=False, allow_none=True)
    nvl_ownerAlias = fields.String(required=False, allow_none=True, data_key="nvl-ownerAlias")
    loadBalancerId = fields.String(required=False, allow_none=True)
    name = fields.String(required=False, allow_none=True)
    state = fields.String(required=False, allow_none=True)
    template = fields.String(required=False, allow_none=True)
    availability_zone = fields.String(required=False, allow_none=True)
    address = fields.String(required=False, allow_none=True)
    security_group = fields.String(required=False, allow_none=True)
    nvl_resourceId = fields.String(required=False, allow_none=True, data_key="nvl-resourceId")


class ResponseMetadataSchema(Schema):
    RequestId = fields.String(required=False, allow_none=True)


class ListLbaasResponseSchema(Schema):
    Lbaas = fields.Nested(LbaasInstanceInfoSchema, many=True)
    Marker = fields.Integer(required=False)
    Total = fields.Integer(required=False)
    Count = fields.Integer(required=False)
    ResponseMetadata = fields.Nested(ResponseMetadataSchema, many=False, required=False, allow_none=True)


# Method View
#
class ListLbaas(ServiceApiView):
    summary = "List Lbaas Instances"
    description = "List Lbaas Instances"
    tags = [SwaggerTAG]

    definitions = {
        "ListLbaasRequestSchema": ListLbaasRequestSchema,
        "ListLbaasResponseSchema": ListLbaasResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(ListLbaasRequestSchema)
    parameters_schema = ListLbaasRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": ListLbaasResponseSchema}})
    response_schema = ListLbaasResponseSchema

    def get(self, controller: ServiceController, data: ListLbaasRequestDict, *args, **kwargs):
        maxRecords = data.get("MaxResults", 100)
        marker = int(data.get("NextToken", 0))

        # check Account
        account_id_list = data.get("owner_id_N", [])

        # get instance identifier
        instance_id_list = data.get("LbInstanceId_N", [])

        # get instance name
        instance_name_list = data.get("LbInstanceName_N", None)
        if instance_name_list is not None:
            instance_name_list = [instance_name_list]

        # get tags
        tag_values = data.get("Nvl_tag_key_N", None)

        res: List[ApiNetworkLbaasInstance]
        # get instances list
        res, total = controller.get_service_type_plugins(
            service_uuid_list=instance_id_list,
            service_name_list=instance_name_list,
            account_id_list=account_id_list,
            servicetags_or=tag_values,
            plugintype=ApiNetworkLbaasInstance.plugintype,
            page=marker,
            size=maxRecords,
        )

        # res:List[ApiNetworkLbaasInstance]
        # format result

        instances_set: List[LbaasInstanceInfoDict] = [r.list_info() for r in res]
        result = {
            "Lbaas": instances_set,
            "Marker": marker,
            "Count": len(instances_set),
            "Total": total,
            "ResponseMetadata": {
                "RequestId": operation.id,
            },
        }
        return result, 200


class AccountListLbaasRequestSchema(Schema):
    oid = fields.String(
        required=True,
        allow_none=True,
        context="path",
        collection_format="multi",
        metadata={"description": "account ID"},
    )

    MaxResults = fields.Integer(
        required=False,
        load_default=10,
        data_key="MaxResults",
        context="query",
        metadata={"description": ""},
    )

    NextToken = fields.String(
        required=False,
        load_default="0",
        data_key="Nvl-NextToken",
        context="query",
        metadata={"description": ""},
    )


class AccountListLbaasRequestDict(TypedDict):
    MaxResults: int
    NextToken: str


class AccountListLbaas(ServiceApiView):
    summary = "List Lbaas Instances"
    description = "List Lbaas Instances"
    tags = ["authority"]

    definitions = {
        "AccountListLbaasRequestSchema": AccountListLbaasRequestSchema,
        "ListLbaasResponseSchema": ListLbaasResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(AccountListLbaasRequestSchema)
    parameters_schema = AccountListLbaasRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": ListLbaasResponseSchema}})
    response_schema = ListLbaasResponseSchema

    def get(self, controller: ServiceController, data: AccountListLbaasRequestDict, oid: str, *args, **kwargs):
        maxRecords = data.get("MaxResults", 1000)
        marker = int(data.get("NextToken", 0))

        # get instance name

        # get tags
        # tag_values = data.get("Nvl_tag_key_N", None)

        res: List[ApiNetworkLbaasInstance]
        # get instances list
        res, total = controller.get_service_type_plugins(
            account_id_list=[oid],
            # servicetags_or=tag_values,
            plugintype=ApiNetworkLbaasInstance.plugintype,
            page=marker,
            size=maxRecords,
        )
        # res:List[ApiNetworkLbaasInstance]
        # format result

        instances_set: List[LbaasInstanceInfoDict] = [r.list_info() for r in res]
        result = {
            "Lbaas": instances_set,
            "Marker": marker,
            "Count": len(instances_set),
            "Total": total,
            "ResponseMetadata": {
                "RequestId": operation.id,
            },
        }
        return result, 200
