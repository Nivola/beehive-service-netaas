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
# from beehive_service.controller import ServiceController

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController


class ApiNetworkHealthMonitor(AsyncApiServiceTypePlugin):
    plugintype = "NetworkHealthMonitor"
    objname = "health_monitor"
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

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.account is None:
            self.post_get()

        # get config
        hm_config = self.get_config("health_monitor")
        if hm_config is None:
            hm_config = {}

        instance_item = {
            "ownerId": self.account.uuid,
            "nvl-ownerAlias": self.account.name,
            "healthMonitorId": self.instance.uuid,
            "name": self.instance.name,
            "state": self.state_mapping(self.instance.status),
            "protocol": hm_config.get("Protocol"),
            "interval": hm_config.get("Interval"),
            "timeout": hm_config.get("Timeout"),
            "maxRetries": hm_config.get("MaxRetries"),
            "method": hm_config.get("Method"),
            "requestURI": hm_config.get("RequestURI"),
            "expected": hm_config.get("Expected"),
            "tagSet": [],
        }

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
        :return: params
        :raise ApiManagerError:
        """
        self.logger.debug("Pre-create params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_update(self, **params):
        """Pre update function. This function is used in update method.

        :param params: input key=value params
        :return: params
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # check type
        if self.is_predefined() is True:
            raise ApiManagerError("Health monitor %s is predefined, cannot be modified" % self.instance.uuid)

        # update service instance configs
        for k, v in params.items():
            self.set_config("health_monitor.%s" % k, v)

        self.logger.debug("Pre-update params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_delete(self, **params):
        """Pre delete function. Use this function to manipulate and validate delete input params.

        :param params: input params
        :return: params
        :raise ApiManagerError:
        """
        # check type
        if self.is_predefined() is True:
            raise ApiManagerError("Health monitor %s is predefined, cannot be deleted" % self.instance.uuid)

        # check is used
        controller = self.controller
        _links, total = controller.get_links(type="tg-hm", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Health monitor %s is in use, cannot be deleted" % self.instance.uuid)

        return params
