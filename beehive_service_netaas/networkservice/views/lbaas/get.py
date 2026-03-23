# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte
from flasgger import fields, Schema
from beehive_service.controller import ServiceController
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from beehive_service_netaas.networkservice.controller  import ApiNetworkLbaasInstance
from .schemacommons import SwaggerTAG
from .list import LbaasInstanceInfoSchema

from beecell.types.bu.lbaas import LbConfigurationSchema
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass

#
# Request
#
class GetLbaasRequestSchema(Schema):
    oid = fields.String(required=True, context="path", metadata={'descriprion':'id, uuid or name oid del lbaas'})


class LbaasDetailSchema(LbaasInstanceInfoSchema):
    lbaas_config = fields.Nested(LbConfigurationSchema, many=True)


#
# Response
#
class GetLbaasResponseSchema(Schema):
    Lbaas = fields.Nested(LbaasDetailSchema, many=False)


#
# Method View 
# 

class GetLbaas(ServiceApiView):
    description = "Get an Lbaas Instance"
    tags = [SwaggerTAG]

    definitions = {
        "GetLbaasRequestSchema": GetLbaasRequestSchema,
        "GetLbaasResponseSchema": GetLbaasResponseSchema,
    }

    parameters = SwaggerHelper().get_parameters(GetLbaasRequestSchema)
    parameters_schema = GetLbaasRequestSchema
    responses = ServiceApiView.setResponses(
        {200: {"description": "success", "schema": GetLbaasResponseSchema}}
    )

    # response_schema = GetLbaasResponseSchema
    def get(self, controller:ServiceController, data, oid: str, *args, **kwargs):
        # get instances list
        serv = controller.get_service_type_plugin(instance=oid, plugin_class=ApiNetworkLbaasInstance,details=True)

        # format result

        result = { "Lbaas": serv.lbaasdetail() }
            
        return result, 200

    pass
