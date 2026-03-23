# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from __future__ import annotations
from copy import deepcopy
from beecell.types.type_string import str2bool
from beehive.common.data import trace
from beehive.common.apimanager import ApiManagerError
# from beehive_service.entity.service_instance import ApiServiceInstance
from beehive_service.entity.service_type import (
    ApiServiceTypeContainer,
    ApiServiceTypePlugin,
    AsyncApiServiceTypePlugin,
)
# from beehive_service.plugins.computeservice.controller import ApiComputeInstance
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

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController


class ApiNetworkListener(AsyncApiServiceTypePlugin):
    plugintype = "NetworkListener"
    objname = "listener"
    create_task = None

    def __init__(self, *args, **kvargs):
        """ """
        ApiServiceTypePlugin.__init__(self, *args, **kvargs)

        self.child_classes = []

    def info(self):
        """Get object info
        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = AsyncApiServiceTypePlugin.info(self)
        info.update({})
        return info

    @staticmethod
    def customize_list(controller, entities, *args, **kvargs):
        """Post list function. Extend this function to execute some operation after entity was created. Used only for
        synchronous creation.

        :param controller: controller instance
        :param entities: list of entities
        :param args: custom params
        :param kvargs: custom params
        :return: None
        :raise ApiManagerError:
        """
        pass

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.account = self.controller.get_account(str(self.instance.account_id))

    @staticmethod
    def state_mapping(state):
        mapping = {
            SrvStatusType.PENDING: "pending",
            SrvStatusType.BUILDING: "building",
            SrvStatusType.CREATED: "building",
            SrvStatusType.ACTIVE: "available",
            SrvStatusType.DELETED: "deleted",
            SrvStatusType.DRAFT: "transient",
            SrvStatusType.ERROR: "error",
        }
        return mapping.get(state, "error")

    def is_predefined(self):
        return str2bool(self.get_config("predefined"))

    def get_traffic_type(self):
        return self.get_config("trafficType")

    def validate_parameters(self, data, *args, **kvargs):
        # check type
        if self.is_predefined() is True:
            raise ApiManagerError("Listener %s is predefined, cannot be modified" % self.instance.uuid)

        # check certificates and ciphering
        traffic_type = self.get_traffic_type()
        if traffic_type in ["https-offloading", "https-end-to-end"]:
            client_cert = data.get("ClientCertificate")
            server_cert = data.get("ServerCertificate")
            if traffic_type == "https-offloading":
                if client_cert is None:
                    raise ApiManagerError("Client certificate is mandatory with %s traffic profile" % traffic_type)
            if traffic_type == "https-end-to-end":
                if client_cert is None:
                    raise ApiManagerError("Client certificate is mandatory with %s traffic profile" % traffic_type)
                if server_cert is None:
                    raise ApiManagerError("Server certificate is mandatory with %s traffic profile" % traffic_type)

        # check persistence
        persistence = data.get("Persistence")
        expire = data.get("ExpireTime")
        if persistence is not None:
            if traffic_type == "ssl-passthrough" and persistence not in ["sourceip", "ssl-sessionid"]:
                raise ApiManagerError("Persistence options for SSL passthrough are: %s" % ["sourceip", "ssl-sessionid"])
            if traffic_type != "ssl-passthrough" and persistence == "ssl-sessionid":
                raise ApiManagerError(
                    "%s persistence can only be applied in conjunction with SSL passthrough profile" % persistence
                )
            if persistence == "cookie":
                cookie_name = data.get("CookieName")
                cookie_mode = data.get("CookieMode")
                if cookie_name is None or cookie_mode is None:
                    raise ApiManagerError(
                        "Cookie name and cookie mode are mandatory with %s persistence type" % persistence
                    )
                if cookie_mode in ["insert", "app-session"] and expire is None:
                    raise ApiManagerError("Expire time cannot be null when cookie mode is insert or app-session")

        # check URL redirection
        redirect_to = data.get("URLRedirect")
        if redirect_to is not None and traffic_type == "ssl-passthrough":
            raise ApiManagerError("URL redirection not available with %s traffic profile" % traffic_type)

        # check X-Forwarded-For HTTP header
        insert_x_forwarded_for = data.get("InsertXForwardedFor")
        if insert_x_forwarded_for is not None and traffic_type in ["tcp", "ssl-passthrough"]:
            raise ApiManagerError("X-Forwarded-For header not available with %s traffic profiles" % traffic_type)

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.account is None:
            self.post_get()

        instance_item = {}

        # get config
        li_config = self.get_config("listener")
        if li_config is None:
            li_config = {}

        instance_item["ownerId"] = self.account.uuid
        instance_item["nvl-ownerAlias"] = self.account.name
        instance_item["listenerId"] = self.instance.uuid
        instance_item["name"] = self.instance.name
        instance_item["desc"] = self.instance.desc
        instance_item["state"] = self.state_mapping(self.instance.status)
        instance_item["trafficType"] = li_config.get("TrafficType")
        persistence = li_config.get("Persistence")
        if persistence is not None:
            instance_item["persistence"] = {
                "method": persistence,
                "cookieName": li_config.get("CookieName"),
                "cookieMode": li_config.get("CookieMode"),
                "expirationTime": li_config.get("ExpireTime"),
            }
        client_cert = li_config.get("ClientCertificate")
        if client_cert is not None:
            instance_item["clientSSL"] = {
                "certificate": "xxxxxxxxxxxxxxx",  # replace with client_cert_id,
                "cipher": li_config.get("ClientCipher"),
            }
        server_cert = li_config.get("ServerCertificate")
        if server_cert is not None:
            instance_item["serverSSL"] = {
                "certificate": "xxxxxxxxxxxxxxx",  # replace with server_cert_id,
                "cipher": li_config.get("ServerCipher"),
            }
        instance_item["insertXForwardedFor"] = li_config.get("InsertXForwardedFor")
        instance_item["urlRedirect"] = li_config.get("URLRedirect")
        instance_item["tagSet"] = []

        res = self.get_config("predefined")
        res = str2bool(res)
        instance_item.update({"predefined": res})
        if res is True:
            instance_item.update({"ext_name": self.get_config("physical_resource")})

        return instance_item

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_update(self, **params):
        """Pre update function. This function is used in update method.

        :param params: input key=value params
        :return: params
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # check type
        if self.is_predefined() is True:
            raise ApiManagerError("Listener %s is predefined, cannot be modified" % self.instance.uuid)

        # update service instance configs
        for k, v in params.items():
            self.set_config("listener.%s" % k, v)

        self.logger.debug("Pre-update params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_delete(self, **params):
        """Pre delete function. Use this function to manipulate and validate delete input params.

        :param params: input params
        :return: kvargs
        :raise ApiManagerError:
        """
        # check type
        if self.is_predefined() is True:
            raise ApiManagerError("Listener %s is predefined, cannot be deleted" % self.instance.uuid)

        # check is used
        controller = self.controller
        _links, total = controller.get_links(type="lb-li", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Listener %s is in use, cannot be deleted" % self.instance.uuid)

        return params

