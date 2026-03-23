# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte
#
# Get
#

from flasgger import fields, Schema
from beehive_service.controller import ServiceController
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from beehive_service_netaas.networkservice.controller  import ApiNetworkLbaasInstance
from .schemacommons import SwaggerTAG
from .list import LbaasInstanceInfoSchema
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass

#
# Request
#
class TestLbaasRequestSchema(Schema):
    oid = fields.String(required=True, context="path", metadata={"description": "id, uuid or name"})

class  LbaasTestSchema(LbaasInstanceInfoSchema):
    config = fields.List(fields.Dict)
#
# Response
class TestLbaasResponseSchema(Schema):
    Lbaas = fields.Nested(LbaasTestSchema, many=False)

#
# Method View
#

class TestLbaas(ServiceApiView):
    description = "Get an Lbaas Instance"
    tags = [SwaggerTAG]
    definitions = {
        "TestLbaasRequestSchema": TestLbaasRequestSchema,
        "TestLbaasResponseSchema": TestLbaasResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(TestLbaasRequestSchema)
    parameters_schema = TestLbaasRequestSchema
    responses = ServiceApiView.setResponses(
        {200: {"description": "success", "schema": TestLbaasResponseSchema}}
    )
    # response_schema = GetLbaasResponseSchema
    def get(self, controller:ServiceController, data, oid: str, *args, **kwargs):
        # get instances list
        serv = controller.get_service_type_plugin(instance=oid, plugin_class=ApiNetworkLbaasInstance,details=True)
        result = { "Lbaas": serv.testdetail() }

        return result, 200

    pass
