# SPDX-License-Identifier: GPL-3.0-or-later
#
# (C) Copyright 2020-2021 Regione Piemonte

from flasgger import Schema
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf
from beehive_service_netaas.networkservice.controller import (
    ApiNetworkService,
    ApiSshGateway,
)
from beehive_service_netaas.networkservice.helper.sshgateway_helper import (
    SshGatewayHelper,
    SshGatewayHelperError,
    SshGwType,
)
from beehive_service.views import ServiceApiView
from beehive.common.apimanager import ApiView, ApiManagerError
from beehive.common.data import operation
from beecell.swagger import SwaggerHelper


class CreateSshGatewayConfResponseNestedSchema(Schema):
    """
    CreateSshGatewayConfResponseNestedSchema
    """

    xmlns = fields.String(required=False, data_key="__xmlns")
    taskid = fields.UUID(required=True, description="task uuid")
    uuid = fields.UUID(required=True, allow_none=False, description="ssh gateway configuration uuid")


class CreateSshGatewayConfResponseSchema(Schema):
    """
    CreateSshGatewayConfResponseSchema
    """

    CreateSshGatewayConfResponse = fields.Nested(
        CreateSshGatewayConfResponseNestedSchema, required=True, allow_none=False
    )


class CreateSshGatewayConfRequestNestedSchema(Schema):
    """
    CreateSshGatewayConfRequestNestedSchema
    """

    name = fields.String(required=True, default="ssh gateway name")
    desc = fields.String(required=False, default="ssh gateway description")
    gw_type = fields.String(
        validate=OneOf(
            [
                SshGwType.DBAAS,
                SshGwType.CPAAS,
            ],
            error="invalid gw_type",
        ),
        description="type of ssh gateway",
        required=True,
    )
    dest_uuid = fields.String(required=False, allow_none=False)
    allowed_ports = fields.List(
        fields.String(example=""),
        required=True,
        allow_none=False,
        collection_format="multi",
        description="allowed ports list",
    )
    forbidden_ports = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        collection_format="multi",
        description="forbidden ports list",
    )


class CreateSshGatewayConfRequestSchema(Schema):
    """
    CreateSshGatewayConfRequestSchema
    """

    configuration = fields.Nested(CreateSshGatewayConfRequestNestedSchema)


class CreateSshGatewayConfBodyRequestSchema(Schema):
    """
    CreateSshGatewayConfBodyRequestSchema
    """

    body = fields.Nested(CreateSshGatewayConfRequestSchema, context="body")


class CreateSshGatewayConf(ServiceApiView):
    """
    CreateSshGatewayConf
    """

    summary = "Create compute ssh gateway configuration"
    description = "Create compute ssh gateway configuration"
    tags = ["networkservice"]  # heading della sezione swagger
    definitions = {
        "CreateSshGatewayConfRequestSchema": CreateSshGatewayConfRequestSchema,
        "CreateSshGatewayConfResponseSchema": CreateSshGatewayConfResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSshGatewayConfBodyRequestSchema)
    parameters_schema = CreateSshGatewayConfRequestSchema
    response_schema = CreateSshGatewayConfResponseSchema
    responses = ServiceApiView.setResponses(
        {202: {"description": "success", "schema": CreateSshGatewayConfResponseSchema}}
    )

    def post(self, controller, data, *args, **kwargs):
        """
        create a new ssh gw destination service instance
        """
        inner_data = data.get("configuration")
        service_definition_id = inner_data.get("service_definition_id")
        name = inner_data.get("name")
        desc = inner_data.get("description", name)
        gw_type = inner_data.get("gw_type", None)
        dest_uuid = inner_data.get("dest_uuid", None)
        allowed_ports = inner_data.pop("allowed_ports", None)
        forbidden_ports = inner_data.pop("forbidden_ports", None)

        # check basic parameter errors
        try:
            dest_account, parsed_ports_set = SshGatewayHelper(controller=controller).check_get_parameters(
                gw_type, dest_uuid, allowed_ports, forbidden_ports
            )
        except SshGatewayHelperError as helper_error:
            raise ApiManagerError(str(helper_error)) from helper_error

        # get definition
        service_definition = controller.get_default_service_def(ApiSshGateway.plugintype)
        if service_definition_id is None:
            service_definition = controller.get_default_service_def(ApiSshGateway.plugintype)
        else:
            service_definition = controller.get_service_def(service_definition_id)

        # check account
        account, parent_plugin = self.check_parent_service(
            controller, dest_account.oid, plugintype=ApiNetworkService.plugintype
        )

        # apply updated params
        inner_data["parsed_ports_set"] = list(parsed_ports_set)  # convert otherwise not json serializable
        inner_data["account_id"] = dest_account.oid
        data["configuration"] = inner_data

        # create service
        plugin: ApiSshGateway
        plugin = controller.add_service_type_plugin(
            service_definition.oid,
            dest_account.oid,
            name=name,
            desc=desc,
            parent_plugin=parent_plugin,
            instance_config=data,
        )

        resp = {
            "CreateSshGatewayConfResponse": {
                "__xmlns": self.xmlns,
                "taskid": plugin.active_task,
                "uuid": plugin.instance.uuid,
            }
        }

        return resp, 202


class DescribeSshGatewayConfResponseSchema(Schema):
    """
    DescribeSshGatewayConfResponseSchema
    """

    sshGatewayConfId = fields.String(required=True, example="12", description="id of the ssh gateway configuration")
    ownerId = fields.String(
        required=True,
        example="",
        description="ID of the account that owns the ssh gateway configuration",
    )
    nvl_ownerAlias = fields.String(
        required=False,
        example="test",
        data_key="nvl-ownerAlias",
        description="alias of the account that owns the ssh gateway configuration",
    )
    nvl_name = fields.String(
        required=False,
        example="test",
        description="ssh gateway configuration name",
        data_key="nvl-name",
    )
    nvl_state = fields.String(required=False, data_key="nvl-state", description="state of the instance object")
    gwType = fields.String(required=False, description="type of ssh gateway")
    destination = fields.String(
        required=True,
        description="uuid of the destination service instance",
    )


class DescribeSshGatewaysConfNestedResponseSchema(Schema):
    """
    DescribeSshGatewaysConfNestedResponseSchema
    """

    xmlns = fields.String(required=False, data_key="__xmlns")
    requestId = fields.String(required=True, allow_none=False, description="Request ID")
    nvl_sshGatewayTotal = fields.Integer(
        required=True,
        example="",
        description="Total number of ssh gateway configurations",
        data_key="nvl-sshGatewayTotal",
    )
    sshGatewaySet = fields.Nested(
        DescribeSshGatewayConfResponseSchema,
        many=True,
        required=True,
        description="List of ssh gateway configurations",
    )


class DescribeSshGatewaysConfResponseSchema(Schema):
    """
    DescribeSshGatewaysConfResponseSchema
    """

    DescribeSshGatewaysConfResponse = fields.Nested(
        DescribeSshGatewaysConfNestedResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class DescribeSshGatewaysConfRequestSchema(Schema):
    """
    DescribeSshGatewaysConfRequestSchema
    """

    owner_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="owner-id.N",
        description="account ID of the ssh gw conf owner",
    )
    sshgwconf_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="sshgwconf-id.N",
        description="ID of the ssh gw conf",
    )
    sshgwconf_name_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="sshgwconf-name.N",
        description="Name of the ssh gw conf",
    )
    tag_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="tag.N",
        description="value of a tag assigned to the resource",
    )
    sshgwconf_type = fields.String(required=False, allow_none=True, data_key="sshgwconf-type")
    size = fields.Integer(required=False, default=10, description="", context="query")
    page = fields.Integer(required=False, default=0, description="", context="query")


class DescribeSshGatewaysConf(ServiceApiView):
    """
    DescribeSshGatewaysConf
    """

    summary = "Describe Ssh Gateway Configurations"
    description = "Describe Ssh Gateway Configurations"
    tags = ["networkservice"]  # heading della sezione swagger
    definitions = {"DescribeSshGatewaysConfResponseSchema": DescribeSshGatewaysConfResponseSchema}
    parameters = SwaggerHelper().get_parameters(DescribeSshGatewaysConfRequestSchema)
    parameters_schema = DescribeSshGatewaysConfRequestSchema
    responses = ServiceApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": DescribeSshGatewaysConfResponseSchema,
            }
        }
    )

    def get(self, controller, data, *args, **kwargs):
        """
        list or get configuration(s)
        """
        # check Account
        account_id_list = data.get("owner_id_N", [])

        # get ids
        sshgwconf_id_list = data.get("sshgwconf_id_N", [])

        # get names
        sshgwconf_name_list = data.get("sshgwconf_name_N", [])

        # get type
        servicetags_or = data.get("tag_N", None)

        res: ApiSshGateway
        res, total = controller.get_service_type_plugins(
            service_uuid_list=sshgwconf_id_list,
            service_name_list=sshgwconf_name_list,
            account_id_list=account_id_list,
            servicetags_or=servicetags_or,
            plugintype=ApiSshGateway.plugintype,
            **data,
        )

        sshgateway_set = [r.aws_info() for r in res]

        resp = {
            "DescribeSshGatewaysConfResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "sshGatewaySet": sshgateway_set,
                "nvl-sshGatewayTotal": total,
            }
        }

        return resp


class DeleteSshGatewayConfResponseItemSchema(Schema):
    """
    DeleteSshGatewayConfResponseItemSchema
    """

    xmlns = fields.String(required=False, data_key="__xmlns")
    requestId = fields.String(required=True, default="The ID of the request")
    nvl_return = fields.Boolean(required=True, example=True, data_key="return")


class DeleteSshGatewayConfResponseSchema(Schema):
    """
    DeleteSshGatewayConfResponseSchema
    """

    DeleteSshGatewayConfResponse = fields.Nested(
        DeleteSshGatewayConfResponseItemSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class DeleteSshGatewayConfRequestSchema(Schema):
    """
    class DeleteSshGatewayConfRequestSchema
    """

    ssh_gateway_id = fields.String(required=True, context="query", description="ssh gateway configuration oid")


class DeleteSshGatewayConfBodyRequestSchema(Schema):
    """
    DeleteSshGatewayConfBodyRequestSchema
    """

    body = fields.Nested(DeleteSshGatewayConfRequestSchema, context="body")


class DeleteSshGatewayConf(ServiceApiView):
    """
    DeleteSshGatewayConf
    """

    summary = "Delete ssh gateway configuration"
    description = "Delete ssh gateway configuration"
    tags = ["networkservice"]  # heading della sezione swagger
    definitions = {
        "DeleteSshGatewayConfRequestSchema": DeleteSshGatewayConfRequestSchema,
        "DeleteSshGatewayConfResponseSchema": DeleteSshGatewayConfResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteSshGatewayConfBodyRequestSchema)
    parameters_schema = DeleteSshGatewayConfRequestSchema
    response_schema = DeleteSshGatewayConfResponseSchema
    responses = ServiceApiView.setResponses(
        {200: {"description": "success", "schema": DeleteSshGatewayConfResponseSchema}}
    )

    def delete(self, controller, data, *args, **kwargs):
        """
        delete ssh gateway configuration
        """
        gateway_id = data.pop("ssh_gateway_id")
        type_plugin = controller.get_service_type_plugin(gateway_id)
        type_plugin.delete()

        res = {
            "DeleteSshGatewayConfResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "return": True,
            }
        }

        return res, 202


class ActivateSshGatewayConfApi1ResponseSchema(Schema):
    """
    ActivateSshGatewayConfApi1ResponseSchema
    """

    requestId = fields.String(required=True, default="", allow_none=True)
    keyMaterial = fields.String(
        required=True,
        allow_none=False,
        example="",
        description="An unencrypted PEM encoded ED private key",
    )
    commandTemplate = fields.String(
        required=True,
        allow_none=False,
        example="ssh -L ...",
        description="ssh local port forwarding sample command",
    )


class ActivateSshGatewayConfApiResponseSchema(Schema):
    """
    ActivateSshGatewayConfApiResponseSchema
    """

    ActivateSshGatewayConfResponse = fields.Nested(
        ActivateSshGatewayConfApi1ResponseSchema, required=True, many=False, allow_none=False
    )


class ActivateSshGatewayConfApiRequestSchema(Schema):
    """
    ActivateSshGatewayConfApiRequestSchema
    """

    ssh_gateway_id = fields.String(required=True, allow_none=False, description="ssh gateway configuration oid")
    destination_port = fields.Int(required=True, allow_none=False, description="destination port")


class ActivateSshGatewayConfBodyRequestSchema(Schema):
    """
    ActivateSshGatewayConfBodyRequestSchema
    """

    body = fields.Nested(ActivateSshGatewayConfApiRequestSchema, context="body")


class ActivateSshGatewayConf(ServiceApiView):
    """
    ActivateSshGatewayConf
    """

    summary = "activate ssh gateway configuration"
    description = "activate ssh gateway configuration"
    tags = ["networkservice"]
    definitions = {
        "ActivateSshGatewayConfApiRequestSchema": ActivateSshGatewayConfApiRequestSchema,
        "ActivateSshGatewayConfApiResponseSchema": ActivateSshGatewayConfApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(ActivateSshGatewayConfBodyRequestSchema)
    parameters_schema = ActivateSshGatewayConfApiRequestSchema
    responses = ServiceApiView.setResponses(
        {202: {"description": "success", "schema": ActivateSshGatewayConfApiResponseSchema}}
    )
    response_schema = ActivateSshGatewayConfApiResponseSchema

    def put(self, controller, data, *args, **kwargs):
        """
        check permission and generate keypair for user
        """
        ssh_gateway_id = data.pop("ssh_gateway_id", None)
        type_plugin: ApiSshGateway = controller.get_service_type_plugin(ssh_gateway_id)
        result = type_plugin.activate_for_user(data)

        response = {
            "ActivateSshGatewayConfResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
            }
        }
        response["ActivateSshGatewayConfResponse"].update(result)
        return response


class NetworkSshGatewayAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/ssh_gateway"
        rules = [
            ("%s/configuration/list" % base, "GET", DescribeSshGatewaysConf, {}),
            ("%s/configuration/create" % base, "POST", CreateSshGatewayConf, {}),
            ("%s/configuration/delete" % base, "DELETE", DeleteSshGatewayConf, {}),
            ("%s/configuration/activate" % base, "PUT", ActivateSshGatewayConf, {}),
        ]
        ApiView.register_api(module, rules, **kwargs)
