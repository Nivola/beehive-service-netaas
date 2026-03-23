# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from flasgger import fields, Schema
from beehive.common.data import operation
from beehive_service.model import SrvStatusType
from beehive_service_netaas.networkservice.controller import ApiNetworkService
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from beehive.common.apimanager import (
    SwaggerApiView,
    CrudApiObjectResponseSchema,
    ApiManagerError,
    ApiView,
    CrudApiObjectTaskResponseSchema,
)
from beehive_service.controller import ApiServiceType


class DescribeNetworkServiceRequestSchema(Schema):
    owner_id = fields.String(
        required=True,
        allow_none=False,
        context="query",
        data_key="owner-id",
        metadata={"description": "account ID of the instance owner"},
    )


class DescribeNetworkServiceItemsSchema(Schema):
    id = fields.String(required=False)
    name = fields.String(required=False)
    description = fields.String(required=False)
    creationDate = fields.String(required=False)
    # account_id = fields.String(required=False)
    # account_name = fields.String(required=False)
    owner = fields.String(required=False)
    owner_name = fields.String(required=False)
    template = fields.String(required=False)
    template_name = fields.String(required=False)
    state = fields.String(required=False, dump_default=SrvStatusType.DRAFT)
    resource_uuid = fields.String(required=False, allow_none=True)
    stateReason = fields.Dict(required=False, dump_default="")
    limits = fields.Dict(required=False, dump_default={})

class DescribeNetworkServiceSchema(Schema):
    xmlns = fields.String(required=False, data_key="__xmlns")
    requestId = fields.String(required=False)
    networkSet = fields.Nested(DescribeNetworkServiceItemsSchema, many=True)
    networkTotal = fields.Integer(required=False)


class DescribeNetworkServiceResponseSchema(Schema):
    DescribeNetworkResponse = fields.Nested(DescribeNetworkServiceSchema, many=False)

class DescribeNetworkService(ServiceApiView):
    summary = "Get network service info"
    description = "Get network service info"
    tags = ["networkservice"]
    definitions = {
        "DescribeNetworkServiceRequestSchema": DescribeNetworkServiceRequestSchema,
        "DescribeNetworkServiceResponseSchema": DescribeNetworkServiceResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DescribeNetworkServiceRequestSchema)
    parameters_schema = DescribeNetworkServiceRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": DescribeNetworkServiceResponseSchema,
            }
        }
    )
    response_schema = DescribeNetworkServiceResponseSchema

    def get(self, controller, data, *args, **kvargs):
        # get instances list
        res, tot = controller.get_service_type_plugins(
            account_id_list=[data.get("owner_id")],
            plugintype=ApiNetworkService.plugintype,
        )
        network_set = [r.aws_info() for r in res]

        res = {
            "DescribeNetworkResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "networkSet": network_set,
                "networkTotal": 1,
            }
        }
        return res


class CreateNetworkServiceApiRequestSchema(Schema):
    owner_id = fields.String(required=True)
    name = fields.String(required=False, dump_default="")
    desc = fields.String(required=False, dump_default="")
    service_def_id = fields.String(required=True, dump_default="")
    resource_desc = fields.String(required=False, dump_default="")


class CreateNetworkServiceApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateNetworkServiceApiRequestSchema, context="body")


class CreateNetworkService(ServiceApiView):
    summary = "Create network service info"
    description = "Create network service info"
    tags = ["networkservice"]
    definitions = {
        "CreateNetworkServiceApiRequestSchema": CreateNetworkServiceApiRequestSchema,
        "CrudApiObjectTaskResponseSchema": CrudApiObjectTaskResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateNetworkServiceApiBodyRequestSchema)
    parameters_schema = CreateNetworkServiceApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {202: {"description": "success", "schema": CrudApiObjectTaskResponseSchema}}
    )
    response_schema = CrudApiObjectTaskResponseSchema

    def post(self, controller, data, *args, **kvargs):
        service_definition_id = data.pop("service_def_id")
        account_id = data.pop("owner_id")
        desc = data.pop("desc", "Network service account %s" % account_id)
        name = data.pop("name")

        plugin = controller.add_service_type_plugin(
            service_definition_id,
            account_id,
            name=name,
            desc=desc,
            instance_config=data,
        )

        uuid = plugin.instance.uuid
        taskid = getattr(plugin, "active_task", None)
        return {"uuid": uuid, "taskid": taskid}, 202


class UpdateNetworkServiceApiRequestParamSchema(Schema):
    owner_id = fields.String(
        required=True,
        allow_none=False,
        context="query",
        data_key="owner-id",
        metadata={"description": "account ID of the instance owner"},
    )
    # params_resource = fields.String(required=False, dump_default='{}')
    name = fields.String(required=False, dump_default="")
    desc = fields.String(required=False, dump_default="")
    service_def_id = fields.String(required=False, dump_default="")


class UpdateNetworkServiceApiRequestSchema(Schema):
    serviceinst = fields.Nested(UpdateNetworkServiceApiRequestParamSchema, context="body")


class UpdateNetworkServiceApiBodyRequestSchema(Schema):
    body = fields.Nested(UpdateNetworkServiceApiRequestSchema, context="body")


class UpdateNetworkService(ServiceApiView):
    summary = "Update network service info"
    description = "Update network service info"
    tags = ["networkservice"]
    definitions = {
        "UpdateNetworkServiceApiRequestSchema": UpdateNetworkServiceApiRequestSchema,
        "CrudApiObjectResponseSchema": CrudApiObjectResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(UpdateNetworkServiceApiBodyRequestSchema)
    parameters_schema = UpdateNetworkServiceApiRequestSchema
    responses = SwaggerApiView.setResponses({200: {"description": "success", "schema": CrudApiObjectResponseSchema}})
    response_schema = CrudApiObjectResponseSchema

    def put(self, controller, data, *args, **kvargs):
        data = data.get("serviceinst")

        def_id = data.get("service_def_id", None)
        account_id = data.get("owner_id")

        inst_services, tot = controller.get_paginated_service_instances(
            account_id=account_id,
            plugintype=ApiNetworkService.plugintype,
            filter_expired=False,
        )
        if tot > 0:
            inst_service = inst_services[0]
        else:
            raise ApiManagerError("Account %s has no network instance associated" % account_id)

        # get service def
        if def_id is not None:
            plugin_root = ApiServiceType(controller).instancePlugin(None, inst=inst_service)
            plugin_root.change_definition(inst_service, def_id)

        return {"uuid": inst_service.uuid}


class DescribeAccountAttributesRequestSchema(Schema):
    owner_id = fields.String(
        required=True,
        allow_none=False,
        context="query",
        data_key="owner-id",
        metadata={"description": "account ID of the instance owner"},
    )

class AttributeValueItemSchema(Schema):
    attributeValue = fields.Integer()
    nvl_attributeUsed = fields.Integer(data_key="nvl-attributeUsed")

class AttributeValueList(Schema):
    item = fields.Nested(AttributeValueItemSchema, many=False)

# class AttributeItemSchem(Schema):

class DescribeAccountAttributeSetResponseSchema(Schema):
    attributeName = fields.String(required=True)
    attributeValueSet = fields.Nested(AttributeValueList, many=True)

class DescribeAccountAttributeResponseSchema(Schema):
    xmlns = fields.String(required=False, data_key="__xmlns")
    requestId = fields.String(required=True, allow_none=True)
    accountAttributeSet = fields.Nested(DescribeAccountAttributeSetResponseSchema, many=True, required=True)


class DescribeAccountAttributesResponseSchema(Schema):
    DescribeAccountAttributesResponse = fields.Nested(
        DescribeAccountAttributeResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class DescribeAccountAttributes(ServiceApiView):
    summary = "Describes attributes of network service"
    description = "Describes attributes of network service"
    tags = ["networkservice"]
    definitions = {
        "DescribeAccountAttributesRequestSchema": DescribeAccountAttributesRequestSchema,
        "DescribeAccountAttributesResponseSchema": DescribeAccountAttributesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DescribeAccountAttributesRequestSchema)
    parameters_schema = DescribeAccountAttributesRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": DescribeAccountAttributesResponseSchema,
            }
        }
    )
    response_schema = DescribeAccountAttributesResponseSchema

    def get(self, controller, data, *args, **kvargs):
        # get instances list
        res, tot = controller.get_service_type_plugins(
            account_id_list=[data.get("owner_id")],
            plugintype=ApiNetworkService.plugintype,
        )
        if tot > 0:
            attribute_set = res[0].aws_get_attributes()
        else:
            raise ApiManagerError("Account %s has no network instance associated" % data.get("owner_id"))

        res = {
            "DescribeAccountAttributesResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "accountAttributeSet": attribute_set,
            }
        }
        return res


class ModifyAccountAttributeBodyRequestSchema(Schema):
    owner_id = fields.String(required=True)
    quotas = fields.Dict(required=True, dump_default="")


class ModifyAccountAttributesBodyRequestSchema(Schema):
    body = fields.Nested(ModifyAccountAttributeBodyRequestSchema, context="body")


class ModifyAccountAttributeSetResponseSchema(Schema):
    uuid = fields.String(required=True, dump_default="")


class ModifyAccountAttributeResponseSchema(Schema):
    requestId = fields.String(required=True, allow_none=True)
    accountAttributeSet = fields.Nested(ModifyAccountAttributeSetResponseSchema, many=True, required=True)


class ModifyAccountAttributesResponseSchema(Schema):
    ModifyAccountAttributesResponse = fields.Nested(
        ModifyAccountAttributeResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class ModifyAccountAttributes(ServiceApiView):
    summary = "Modify attributes of network service"
    description = "Modify attributes of network service"
    tags = ["networkservice"]
    definitions = {
        "ModifyAccountAttributeBodyRequestSchema": ModifyAccountAttributeBodyRequestSchema,
        "ModifyAccountAttributesResponseSchema": ModifyAccountAttributesResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ModifyAccountAttributesBodyRequestSchema)
    parameters_schema = ModifyAccountAttributeBodyRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": DescribeAccountAttributesResponseSchema,
            }
        }
    )
    response_schema = DescribeAccountAttributesResponseSchema

    def put(self, controller, data, *args, **kvargs):
        # get instances list
        res, tot = controller.get_service_type_plugins(
            account_id_list=[data.get("owner_id")],
            plugintype=ApiNetworkService.plugintype,
        )
        if tot > 0:
            res[0].set_attributes(data.get("quotas"))
            attribute_set = [{"uuid": res[0].instance.uuid}]
        else:
            raise ApiManagerError("Account %s has no network instance associated" % data.get("owner_id"))

        res = {
            "ModifyAccountAttributesResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "": attribute_set,
            }
        }
        return res


class DeleteNetworkServiceResponseSchema(Schema):
    uuid = fields.String(required=True, metadata={"description": "Instance is"})
    taskid = fields.String(required=True, metadata={"description": "task id"})


class DeleteNetworkServiceRequestSchema(Schema):
    instanceId = fields.String(
        required=True,
        allow_none=True,
        context="query",
        metadata={"description": "Instance uuid or name"},
    )


class DeleteNetworkService(ServiceApiView):
    summary = "Terminate a network service"
    description = "Terminate a network service"
    tags = ["networkservice"]
    definitions = {
        "DeleteNetworkServiceRequestSchema": DeleteNetworkServiceRequestSchema,
        "DeleteNetworkServiceResponseSchema": DeleteNetworkServiceResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteNetworkServiceRequestSchema)
    parameters_schema = DeleteNetworkServiceRequestSchema
    responses = SwaggerApiView.setResponses(
        {202: {"description": "success", "schema": DeleteNetworkServiceResponseSchema}}
    )
    response_schema = DeleteNetworkServiceResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        instance_id = data.pop("instanceId")

        type_plugin = controller.get_service_type_plugin(instance_id, plugin_class=ApiNetworkService)
        type_plugin.delete()

        uuid = type_plugin.instance.uuid
        taskid = getattr(type_plugin, "active_task", None)
        return {"uuid": uuid, "taskid": taskid}, 202


class NetworkServiceAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = "nws"
        rules = [
            ("%s/networkservices" % base, "GET", DescribeNetworkService, {}),
            ("%s/networkservices" % base, "POST", CreateNetworkService, {}),
            ("%s/networkservices" % base, "PUT", UpdateNetworkService, {}),
            ("%s/networkservices" % base, "DELETE", DeleteNetworkService, {}),
            (
                "%s/networkservices/describeaccountattributes" % base,
                "GET",
                DescribeAccountAttributes,
                {},
            ),
            (
                "%s/networkservices/modifyaccountattributes" % base,
                "PUT",
                ModifyAccountAttributes,
                {},
            ),
        ]

        ApiView.register_api(module, rules, **kwargs)
