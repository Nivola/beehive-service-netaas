# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from flasgger import fields, Schema
from beehive_service.controller import ServiceController
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from beehive_service_netaas.networkservice.controller  import ApiNetworkLbaasInstance
from beehive_service_netaas.networkservice.controller import ApiNetworkLbaasInstance
from beecell.types.bu.lbaas import UpdateLbaasDict, UpdateLbaasSchema
from .schemacommons import SwaggerTAG
from typing import TYPE_CHECKING, TypedDict


#
# Request
#
class UpdateLbaasRequestSchema(Schema):
    Lbaas = fields.Nested(UpdateLbaasSchema, many=False, required=True, allow_none=False)


class UpdateLbaasRequestBodySchema(Schema):
    oid = fields.String(required=True, context="path", metadata={"description": "id, uuid or name"})
    body = fields.Nested(UpdateLbaasRequestSchema, required=True, context="body") 

class UpdateLbaasRequestDict(TypedDict):
    Lbaas: UpdateLbaasDict


#
# Response
#


class UpdateLbaasResponseSchema(Schema):
    lbaasIdentifier = fields.String(required=False, metadata={"description": "Lbaas uuid"})
    lbaasState = fields.String(required=True, metadata={"description": "Lbaas State"})


#
# Method View
#


class UpdateLbaas(ServiceApiView):
    summary = "Lbaas Instances Creation"
    description = "Lbaas Instances Creation"
    tags = [SwaggerTAG]

    definitions = {
        "UpdateLbaasRequestSchema": UpdateLbaasRequestSchema,
        "UpdateLbaasRequestSchema": UpdateLbaasRequestSchema,
    }

    parameters = SwaggerHelper().get_parameters(UpdateLbaasRequestBodySchema)
    parameters_schema = UpdateLbaasRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": UpdateLbaasResponseSchema}})
    response_schema = UpdateLbaasResponseSchema

    pass

    def put(self, controller: ServiceController, data: UpdateLbaasRequestDict,oid:str, *args, **kwargs):
        lbaas_instance = controller.get_service_type_plugin(instance=oid, plugin_class=ApiNetworkLbaasInstance,details=True)
        lbaas_instance.instance.verify_permisssions("update")
        
        lbaas_data: UpdateLbaasDict = data.get("Lbaas")
        
        paswd = lbaas_data.get("user_password")
        if paswd is not None:
            lbaas_instance.user_pasword = paswd
            
        cfg = lbaas_data.get("lbaasconfig")
        if cfg is not None:
            lbaas_instance.lbaas_config = cfg
            
        lbaas_instance.save_lbaas_configs()
        res = lbaas_instance.applyconfiguration()
        
        res = {
            "lbaasIdentifier": lbaas_instance.instance.uuid,
            "lbaasState": lbaas_instance.status,
        }

        return res, 202


class PatchLbaasRequestSchema(Schema):
    oid = fields.String(required=True, description="id, uuid or name", context="path")

class PatchLbaasResponseSchema(Schema):
    msg = fields.String(required=True, )


class PatchLbaas(ServiceApiView):
    summary = "Lbaas Instances Patch"
    description = "Lbaas Instances Patch update attributes from provided resources"
    tags = [SwaggerTAG]
    definitions = {
        "PatchLbaasRequestSchema": PatchLbaasRequestSchema,
        "PatchLbaasRequestSchema": PatchLbaasRequestSchema,
    }
    parameters = SwaggerHelper().get_parameters(PatchLbaasRequestSchema)
    # parameters_schema = PatchLbaasRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": PatchLbaasResponseSchema}})
    response_schema = PatchLbaasResponseSchema

    pass

    def patch(self, controller: ServiceController, data, oid:str, *args, **kwargs):
        lbaas_instance = controller.get_service_type_plugin(instance=oid, plugin_class=ApiNetworkLbaasInstance,details=True)
        lbaas_instance.instance.verify_permisssions("update")
        lbaas_instance.get_attr_from_res()
        
        res = {
            "msg": "OK",
        }

        return res, 200
