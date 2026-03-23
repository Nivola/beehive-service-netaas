#!/usr/bin/env python
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2026 CSI-Piemonte


from __future__ import annotations
from ast import List
from flasgger import fields, Schema
from beecell.swagger import SwaggerHelper
from beehive.common.apimanager import SwaggerApiView
from beehive.common.data import operation
from beehive_service.views import ServiceApiView
from .schemacommons import SwaggerTAG
from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from beehive_service.controller import ServiceController
    from beehive_service.controller.api_account import ApiAccount



class LbaasFlavourItem(Schema):
    name = fields.String(required=True, metadata={"description": "temmplate name"})
    description = fields.String(required=True, metadata={"description": "template description"})

class LbaasFlavourResponse(Schema):
        # "$xmlns": self.xmlns,
    requestId = fields.String(required=True)
    flavours = fields.Nested(LbaasFlavourItem, many=True)
    flavoursTotal = fields.Integer(required=True)


class AccountLbaasFlavourRequestSchema(Schema):
    oid = fields.String(required=True, context="path", metadata={"description": "id, uuid or name"})

class AccountLbaasFlavours(ServiceApiView):
    summary = "List of Lbaas template for account"
    description = "List of Lbaas template for account"
    tags = ["authority"]
    definitions = {"LbaasFlavourResponse": LbaasFlavourResponse}
    parameters = SwaggerHelper().get_parameters(AccountLbaasFlavourRequestSchema)

    responses = SwaggerApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": LbaasFlavourResponse,
            }
        }
    )
    response_schema =LbaasFlavourResponse

    def get(self, controller: ServiceController, data, oid: str, *args, **kwargs):
        account_id = oid
        account: ApiAccount = controller.get_account(account_id)

        # instance_engines_set, total = controller.get_catalog_service_definitions(plugintype='VirtualService')
        # self.logger.warn(instance_engines_set)

        lbaas_set, total = account.get_definitions(plugintype="NetworkLbaasInstance", size=-1)
        total = 0
        res_type_set : List[dict]= []
        for r in lbaas_set:
            res_type_set.append({
                'name': r.name,
                'description': r.desc,
            })

            total += 1

        res = {
                # "$xmlns": self.xmlns,
                "requestId": operation.id,
                "flavours": res_type_set,
                "flavoursTotal": total,
        }
        return res


class LbaasFlavours(ServiceApiView):
    summary = "List of Lbaas template"
    description = "List of Lbaas template"
    tags = [SwaggerTAG]
    definitions = {"LbaasFlavourResponse": LbaasFlavourResponse}
    parameters = SwaggerHelper().get_parameters(AccountLbaasFlavourRequestSchema)
    responses = SwaggerApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": LbaasFlavourResponse,
            }
        }
    )
    response_schema =LbaasFlavourResponse

    def get(self, controller: ServiceController, data, *args, **kwargs):

        # instance_engines_set, total = controller.get_catalog_service_definitions(plugintype='VirtualService')
        # self.logger.warn(instance_engines_set)

        lbaas_set= controller.get_service_defs(plugintype="NetworkLbaasInstance", namelike=True, size=-1)
        total = 0
        res_type_set : List[dict]= []
        for r in lbaas_set:
            res_type_set.append({
                'name': r.name,
                'description': r.desc,
            })
            total += 1


        res = {
                # "$xmlns": self.xmlns,
                "requestId": operation.id,
                "flavours": res_type_set,
                "flavoursTotal": total,
        }
        return res
