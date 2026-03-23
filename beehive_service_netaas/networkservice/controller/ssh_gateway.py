# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from __future__ import annotations
from copy import deepcopy
from beecell.types.type_string import str2bool
from beehive.common.data import trace
from beehive.common.apimanager import ApiManagerError
from beehive_service.entity.service_instance import ApiServiceInstance
from beehive_service.entity.service_type import (
    ApiServiceTypeContainer,
    ApiServiceTypePlugin,
    AsyncApiServiceTypePlugin,
)
from beehive_service.plugins.computeservice.controller import ApiComputeInstance
# from six.moves.urllib.parse import urlencode
from urllib.parse import urlencode
from beehive_service.model import SrvStatusType
from beecell.simple import (
    format_date,
    truncate,
    obscure_data,
    id_gen,
    dict_get,
    random_password,
)
from beehive_service.controller import ServiceController

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController





class ApiSshGateway(AsyncApiServiceTypePlugin):
    plugintype = "NetworkSshGateway"
    objname = "ssh_gateway"

    class state_enum(object):
        """enumerate state name esposed by api"""

        unknown = "unknown"
        pending = "pending"
        available = "available"
        deregistered = "deregistered"
        transient = "transient"
        error = "error"

    def __init__(self, *args, **kvargs):
        """init"""
        ApiServiceTypePlugin.__init__(self, *args, **kvargs)

        self.child_classes = []

    def info(self):
        """Get object info
        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = AsyncApiServiceTypePlugin.info(self)
        return info

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: self.state_enum.pending,
            SrvStatusType.ACTIVE: self.state_enum.available,
            SrvStatusType.DELETED: self.state_enum.deregistered,
            SrvStatusType.DRAFT: self.state_enum.transient,
            SrvStatusType.ERROR: self.state_enum.error,
        }
        return mapping.get(state, self.state_enum.unknown)

    def aws_info(self):
        """Get info as required by aws api
        :param inst_service:
        :param resource:
        :param account_idx:
        :param instance_type_idx:
        :return:
        """
        # get config
        config = self.get_config("configuration")
        if config is None:
            config = {}

        instance_item = {}
        if self.resource is None:
            self.resource = {}

        instance_item["ownerId"] = self.account.uuid
        instance_item["sshGatewayConfId"] = self.instance.uuid
        instance_item["nvl-state"] = self.state_mapping(self.instance.status)

        # custom params
        instance_item["nvl-name"] = self.instance.name
        instance_item["nvl-ownerAlias"] = self.account.name
        if self.instance.status == SrvStatusType.ERROR:
            instance_item["stateReason"] = {
                "code": 400,
                "message": self.instance.last_error,
            }
        instance_item["gwType"] = config["gw_type"]
        instance_item["destination"] = config.get("dest_uuid", None)
        instance_item["parsed_ports_set"] = config.get("parsed_ports_set", None)

        try:
            instance_item["resource"] = self.resource
        except AttributeError:
            pass

        return instance_item

    @staticmethod
    def customize_list(controller: ServiceController, entities, *args, **kvargs):
        """
        :param controller: controller instance
        :param entities: list of entities (List[ApiSshGateway])
        :param args: custom params
        :param kvargs: custom params
        :return: entities
        :raise ApiManagerError:
        """

        account_idx = controller.get_account_idx()
        instance_type_idx = controller.get_service_definition_idx(ApiSshGateway.plugintype)

        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.account = account_idx.get(account_id)

            # get instance type
            entity.instance_type = instance_type_idx.get(str(entity.instance.service_definition_id))

        return entities

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for
        service creation.
        Extend this function to manipulate and validate create input params.

        :param params: input params
            'alias': 'NetworkSshGateway.create',
            'id', 'uuid', 'objid', 'name', 'desc', 'attribute': None, 'tags': None
        :return: resource input params
        :raise ApiManagerError:
        """
        rp = self.get_config("configuration")  # parametri passati alla post
        dest_uuid = rp.get("dest_uuid")
        db_or_cp_inst = self.controller.get_service_instance(dest_uuid)

        # link to destination
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, db_or_cp_inst.oid),
            type="ssh_gw",
            end_service=db_or_cp_inst.oid,
            attributes={},
        )

        return params

    def post_delete(self, **params):
        """Post delete function. This function is used in delete method. Extend this function to execute action after
        object was deleted.

        :param params: input params
        :return: None
        :raise ApiManagerError:
        """
        # delete all links
        links, _tot = self.controller.get_links(service=self.instance.oid)
        for link in links:
            self.logger.debug("expunge link %s" % link.uuid)
            link.expunge()

        return None

    def activate_for_user(self, params):
        # check you can use this sshgw conf
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "use",
        )

        config = self.get_config("configuration")
        try:
            dest_uuid = config.get("dest_uuid", None)
            dest = self.controller.get_service_instance(dest_uuid)
        except ApiManagerError as am_err:
            # change status to error only when destination not found
            self.update_status(SrvStatusType.ERROR, error=am_err.value)
            raise ApiManagerError(
                "Error fetching destination info (dest_uuid:%s): %s." % (dest_uuid, am_err.value)
            ) from am_err

        # check you can use destination
        self.controller.check_authorization(ApiServiceInstance.objtype, ApiServiceInstance.objdef, dest.objid, "use")

        allowed = False
        port = params.get("destination_port", None)
        try:
            parsed_ports_set = config.get("parsed_ports_set", None)
            for from_to in parsed_ports_set:
                if port >= from_to[0] and port <= from_to[1]:
                    allowed = True
                    break
        except Exception as ex:
            raise ApiManagerError(ex) from ex

        if not allowed:
            raise ApiManagerError(f"Forbidden port: {port}")

        from beehive.common.data import operation

        # operation = [ user_email user_ip user_token ]
        user_id = self.controller.api_manager.get_identity(operation.user[2]).get("user").get("id")
        try:
            data = {"user": user_id, "destination": dest.resource_uuid, "port": port}
            uri = "/v1.0/nrs/provider/ssh_gateway/activate"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            raise ApiManagerError(str(ex))

        return res
