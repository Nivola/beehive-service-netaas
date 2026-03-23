# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from math import inf
from flasgger import fields, Schema
from beehive.common.apimanager import SwaggerApiView
from beehive_service_netaas.networkservice.controller.network_lbaas import LbaasInstanceInfoDict
from beehive.common.data import operation
from beehive_service.controller import ServiceController
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper

# from marshmallow.decorators import validates_schema
from beehive_service_netaas.networkservice.controller import ApiNetworkLbaasInstance
from .schemacommons import SwaggerTAG
from .list import LbaasInstanceInfoSchema, LbaasInstanceInfoDict

from typing import TYPE_CHECKING, TypedDict

#
# Request
#

#
# Response
#


#
# Method View
#


class DeleteLbaasRequestSchema(Schema):
    oid = fields.String(required=True, context="path", metadata={"description": "id, uuid or name"})


class DeleteLbaasResponseSchema(Schema):
    requestId = fields.String(required=True, metadata={"example": "erc453", "description": "request id"})
    deleting = fields.Nested(LbaasInstanceInfoSchema, many=False, required=False)
    return_status = fields.Boolean(
        required=True,
        data_key="return",
        metadata={"example": True, "description": "Is true if the request succeeds, and an error otherwise"},
    )
    nvl_activeTask = fields.String(
        required=True,
        allow_none=True,
        data_key="nvl-activeTask",
        metadata={"description": "active task id"},
    )


DeleteLbaasResponseDict = TypedDict(
    "DeleteLbaasResponseDict",
    {
        "requestId": str,
        "deleting": LbaasInstanceInfoDict,
        "return": bool,
        "nvl-activeTask": str,
    },
)


class DeleteLbaas(ServiceApiView):
    summary = "Delete load balancer"
    description = "Delete load balancer"
    tags = [SwaggerTAG]

    definitions = {
        "DeleteLbaasRequestSchema": DeleteLbaasRequestSchema,
        "DeleteLbaasResponseSchema": DeleteLbaasResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(DeleteLbaasRequestSchema)
    # parameters_schema = DeleteLbaasRequestSchema
    responses = SwaggerApiView.setResponses({200: {"description": "success", "schema": DeleteLbaasResponseSchema}})
    response_schema = DeleteLbaasResponseSchema

    def delete(self, controller: ServiceController, data, oid: str, *args, **kwargs):
        lbaas_instance: ApiNetworkLbaasInstance = controller.get_service_type_plugin(
            oid, plugin_class=ApiNetworkLbaasInstance
        )

        info = lbaas_instance.list_info()
        lbaas_instance.delete()

        res: DeleteLbaasResponseDict = {
            "deleting": info,
            "nvl-activeTask": lbaas_instance.active_task,
            "requestId": operation.id,
            "nvl-activeTask": lbaas_instance.action_task,
            "return": True,
        }

        return res, 200
