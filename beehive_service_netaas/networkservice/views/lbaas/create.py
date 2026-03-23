# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from beehive.common.apimanager import ApiManagerError
from beehive_service.controller import ServiceController, ApiAccount
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger import fields, Schema
from beehive_service_netaas.networkservice.controller import ApiNetworkLbaasInstance, ApiNetworkService
from beehive_service_netaas.networkservice.validation import validate_network
from beecell.types.bu.lbaas import LbaasSchema, LbaasDict,  LbaasTemplateDict
from .schemacommons import SwaggerTAG
from typing import TYPE_CHECKING, TypedDict
if TYPE_CHECKING:
    pass

#
# Request
#
class CreateLbaasRequestSchema(Schema):
    Lbaas = fields.Nested(LbaasSchema, many=False, required=True, allow_none=False)


class CreateLbaasRequestBodySchema(Schema):
    body = fields.Nested(CreateLbaasRequestSchema, required=True, context="body") 

class CreateLbaasRequestDict(TypedDict):
    Lbaas: LbaasDict


#
# Response
#


class CreateLbaasResponseSchema(Schema):
    lbaasIdentifier = fields.String(required=False, metadata={"description": "Lbaas uuid"})
    lbaasState = fields.String(required=True, metadata={"description": "Lbaas State"})


#
# Method View
#


class CreateLbaas(ServiceApiView):
    summary = "Lbaas Instances Creation"
    description = "Lbaas Instances Creation"
    tags = [SwaggerTAG]

    definitions = {
        "CreateLbaasRequestSchema": CreateLbaasRequestSchema,
        "CreateLbaasResponseSchema": CreateLbaasResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(CreateLbaasRequestBodySchema)
    parameters_schema = CreateLbaasRequestSchema
    responses = ServiceApiView.setResponses({200: {"description": "success", "schema": CreateLbaasResponseSchema}})
    response_schema = CreateLbaasResponseSchema

    pass

    def post(self, controller: ServiceController, data: CreateLbaasRequestDict, *args, **kwargs):
        lbaas_data: LbaasDict = data.get("Lbaas")

        account_id = lbaas_data.get("account_id")
        name = lbaas_data.get("instance_identifier")
        desc = name

        # check instance with the same name already exists
        self.service_exist(controller, name, ApiNetworkLbaasInstance.plugintype)

        if TYPE_CHECKING:
            parent_inst: ApiNetworkService
            account: ApiAccount

        # get parent
        account, parent_inst = controller.check_service_type_plugin_parent_service(
            account_id, plugintype=ApiNetworkService.plugintype
        )

        # get lbaas flavour

        # get template service definition with engine configuration
        template_name = "lbaas-config-%s" % (lbaas_data.get("template", "default"))
        print(template_name)
        template_defs, tot = account.get_definitions(service_definition_id=template_name, plugintype="VirtualService")
        if len(template_defs) < 1 or len(template_defs) > 1:
            raise ApiManagerError("Labaas template  %s was not found" % (template_name))
        template_config = template_defs[0].get_main_config().params

        # add engine config
        lbaas_data["engine_config"] = template_config

        # check service definition for flacour
        # get flavour no check neede for accont  (done by add_service_type_plugin controllert method)
        flavour_name = lbaas_data.get("flavour", "lbaas_medium")
        flavour_definition_id = controller.get_definition_id(flavour_name)

        # create service instance
        lbaas_data["computeZone"] = parent_inst.instance.resource_uuid
        inst = controller.add_service_type_plugin(
            flavour_definition_id,
            account_id,
            name=name,
            desc=desc,
            parent_plugin=parent_inst,
            instance_config=lbaas_data,
        )

        res = {
            "lbaasIdentifier": inst.instance.uuid,
            "lbaasState": inst.status,
        }

        return res, 202
