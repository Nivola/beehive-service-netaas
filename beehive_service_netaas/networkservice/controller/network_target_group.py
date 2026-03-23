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
from .network_health_monitor import ApiNetworkHealthMonitor        
        
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController


class ApiNetworkTargetGroup(AsyncApiServiceTypePlugin):
    plugintype = "NetworkTargetGroup"
    objname = "target_group"
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

    def __get_target_type_plugin(self, target_id, target_type):
        return self.controller.get_service_type_plugin(
            target_id, plugin_class=ApiNetworkTargetGroup.__type_mapping(target_type)
        )

    def __get_target_info(self, target, target_type):
        target_id = target.get("Id")
        type_plugin = self.__get_target_type_plugin(target_id, target_type)

        # get vm ip address
        ip_address = None
        if target_type == "vm":
            res = type_plugin.get_resource()
            vpcs = res.get("vpcs", [])
            ip_address = dict_get(vpcs[0], "fixed_ip.ip")

        return {
            "id": target_id,
            "name": target.get("Name"),
            "state": type_plugin.instance.status,
            "ip_address": ip_address,
            "lb_port": target.get("LbPort"),
            "hm_port": target.get("HmPort"),
            "site": target.get("site"),
            "avz": target.get("avz"),
            "resource_uuid": target.get("ResourceUuid"),
        }

    def __get_object_info(self, oid, plugin_class):
        info = {}
        if oid is not None:
            type_plugin = self.controller.get_service_type_plugin(oid, plugin_class=plugin_class)
            info = type_plugin.aws_info()
        return info

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.account is None:
            self.post_get()

        # get config
        tg_config = self.get_config("target_group")
        if tg_config is None:
            tg_config = {}

        instance_item = {
            "ownerId": self.account.uuid,
            "nvl-ownerAlias": self.account.name,
            "targetGroupId": self.instance.uuid,
            "name": self.instance.name,
            "desc": self.instance.desc,
            "state": self.state_mapping(self.instance.status),
            "balancingAlgorithm": tg_config.get("BalancingAlgorithm"),
            "targetType": tg_config.get("TargetType"),
            "transparent": tg_config.get("Transparent"),
            "attachmentSet": {},
            "tagSet": [],
        }

        # get targets info
        targets = tg_config.get("Targets", [])
        target_type = tg_config.get("TargetType")
        d = {
            "TargetSet": {
                "Targets": [self.__get_target_info(target, target_type) for target in targets],
                "totalTargets": len(targets),
            }
        }
        instance_item["attachmentSet"].update(d)

        # get health monitor info
        d = {"HealthMonitor": self.__get_object_info(tg_config.get("HealthMonitor"), ApiNetworkHealthMonitor)}
        instance_item["attachmentSet"].update(d)

        return instance_item

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        data_instance = self.get_config("target_group")
        health_monitor_id = data_instance.get("HealthMonitor")

        controller: ServiceController = self.controller
        if health_monitor_id is not None:
            # check health monitor exists and is active
            hm_plugin: ApiNetworkHealthMonitor
            hm_plugin = controller.get_service_type_plugin(health_monitor_id, plugin_class=ApiNetworkHealthMonitor)
            self.hm_plugin = hm_plugin 

            # check health monitor is already used
            _links, total = self.controller.get_links(type="tg-hm", end_service=hm_plugin.instance.oid)
            if total != 0 and not hm_plugin.is_predefined():
                raise ApiManagerError(
                    "Health monitor %s already registered with a target group. Deregister health "
                    "monitor from target group before attaching it to new target group" % hm_plugin.instance.oid
                )

            # check target group has already a health monitor attached
            _links, total = self.controller.get_links(type="tg-hm", start_service=self.instance.oid)
            if total != 0:
                raise ApiManagerError(
                    "Target group %s already has a health monitor attached. Deregister attached "
                    "health monitor from target group before attaching new health monitor" % self.instance.oid
                )

            # add link between target group and health monitor
            self.add_link(
                name="link-%s-%s" % (self.instance.oid, hm_plugin.instance.oid),
                type="tg-hm",
                end_service=hm_plugin.instance.oid,
                attributes={},
            )

            # update target group configs
            self.set_config("target_group.HealthMonitor", hm_plugin.instance.uuid)

        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_update(self, **params):
        """Pre update function. This function is used in update method.

        :param params: input key=value params
        :return: params
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # update service instance configs
        for k, v in params.items():
            self.set_config("target_group.%s" % k, v)

        self.logger.debug("Pre-update params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_delete(self, **params):
        """Pre delete function. Use this function to manipulate and validate delete input params.

        :param params: input params
        :return: kvargs
        :raise ApiManagerError:
        """
        tg_config = self.get_config("target_group")
        hm_id = tg_config.get("HealthMonitor")

        # controller: ServiceController = self.controller

        # check is used
        links, total = self.controller.get_links(type="lb-tg", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Target group %s is in use, cannot be deleted" % self.instance.uuid)

        links, tot = self.controller.get_links(start_service=self.instance.oid, type="tg-t")
        for link in links:
            # remove reference to target group in balanced target
            link_info = link.info()
            end_service_uuid = dict_get(link_info, "details.end_service.uuid")
            end_service_inst = self.controller.get_service_instance(end_service_uuid)
            target_groups = end_service_inst.get_config("instance.nvl-targetGroups")
            target_groups.remove(self.instance.uuid)
            if not target_groups:
                target_groups = None
            end_service_inst.set_config("instance.nvl-targetGroups", target_groups)
            # delete link to target
            link.expunge()

        # remove link to health monitor
        links, tot = self.controller.get_links(start_service=self.instance.oid, type="tg-hm")
        if tot == 1:
            links[0].expunge()

        # delete custom health monitor instance only
        try:
            type_plugin = self.controller.get_service_type_plugin(hm_id)
            if type_plugin.is_predefined() is False:
                type_plugin.delete()
        except Exception:
            pass

        return params

    #
    # Actions
    #
    @staticmethod
    def __type_mapping(target_type) -> dict:
        mapping = {"vm": ApiComputeInstance}
        return mapping.get(target_type)

    def __check_availability_zone(self, target_avz):
        avz = self.get_config("target_group.avz")
        if avz is None:
            self.set_config("target_group.avz", target_avz)
            return
        if avz != target_avz:
            raise ApiManagerError("Availability zone mismatch, all targets must belong to the same availability zone")

    @staticmethod
    def __is_target_registered(type_plugin, targets):
        idx = 0
        for target in targets:
            if type_plugin.instance.uuid == target.get("Id"):
                return idx
            idx = idx + 1
        return -1

    def register_targets(self, targets):
        """Register targets with target group

        :param targets: list of target ids and ports
        :return: True
        """
        self.controller: ServiceController

        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # get target group configuration
        tg_config = self.get_config("target_group")
        target_type = tg_config.get("TargetType")
        registered_targets = tg_config.get("Targets", [])

        new_targets = []
        for target in targets:
            target_id = target.get("Id")
            target_lb_port = target.get("LbPort")
            target_hm_port = target.get("HmPort")
            if target_hm_port is None:
                target_hm_port = target_lb_port

            # check target exists and its type matches the target group type
            type_plugin = self.__get_target_type_plugin(target_id, target_type)

            # get target site id - !!! invoked method name is misleading !!!
            target_site_id = type_plugin.get_resource_main_availability_zone()

            # get target service instance
            service_inst: ApiServiceInstance = type_plugin.instance

            # get related compute zone uuid
            compute_zone_uuid = service_inst.get_config("computeZone")

            # get target availability zone
            target_avz: dict = type_plugin.get_resource_availability_zone_by_site(compute_zone_uuid, target_site_id)

            # check availability zone consistency
            self.__check_availability_zone(target_avz.get("uuid"))

            # add link to target if target is not registered yet
            _links, total = self.controller.get_links(
                type="tg-t",
                start_service=self.instance.oid,
                end_service=service_inst.oid,
            )

            if total != 0:
                raise ApiManagerError(
                    "Target %s already registered with target group %s" % (service_inst.uuid, self.instance.uuid)
                )
            self.add_link(
                name="link-%s-%s" % (self.instance.oid, service_inst.oid),
                type="tg-t",
                end_service=service_inst.oid,
                attributes={},
            )

            # update target config
            tgs = service_inst.get_config("instance.nvl-targetGroups")
            if tgs is None:
                tgs = []
            if self.instance.uuid not in tgs:
                tgs.append(self.instance.uuid)
            service_inst.set_config("instance.nvl-targetGroups", tgs)

            new_targets.append(
                {
                    "Id": service_inst.uuid,
                    "Name": service_inst.name,
                    "LbPort": target_lb_port,
                    "HmPort": target_hm_port,
                    "ResourceUuid": service_inst.resource_uuid,
                    "avz": {
                        "id": target_avz.get("id"),
                        "uuid": target_avz.get("uuid"),
                        "name": target_avz.get("name"),
                    },
                    "site": {
                        "id": dict_get(target_avz, "site.id"),
                        "uuid": dict_get(target_avz, "site.uuid"),
                        "name": dict_get(target_avz, "site.name"),
                    },
                }
            )

        # update target group config
        registered_targets.extend(new_targets)
        self.set_config("target_group.Targets", registered_targets)

        return True

    def deregister_targets(self, targets):
        """Deregister a list of targets from a target group

        :param targets: list of target ids
        :return: True
        """
        self.controller: ServiceController

        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # get target group config
        tg_config = self.get_config("target_group")
        target_type = tg_config.get("TargetType")
        registered_targets = tg_config.get("Targets", [])

        for target in targets:
            target_id = target.get("Id")

            # check target exists and its type matches the target group type
            type_plugin = self.__get_target_type_plugin(target_id, target_type)

            # check target to detach is in target group registered targets set
            idx = self.__is_target_registered(type_plugin, registered_targets)
            if idx == -1:
                raise ApiManagerError("Target to deregister not found in target group %s" % self.instance.uuid)

            # delete link between target group and target
            service_inst: ApiServiceInstance = type_plugin.instance
            _links, total = self.controller.get_links(
                type="tg-t",
                start_service=self.instance.oid,
                end_service=service_inst.oid,
            )
            if total != 1:
                ApiManagerError(
                    "Link between target group %s and target %s not found" % (self.instance.uuid, service_inst.uuid)
                )
            self.del_link(service_inst.oid, "tg-t")

            # update target config
            tgs = service_inst.get_config("instance.nvl-targetGroups")
            if tgs is not None and self.instance.uuid in tgs:
                tgs.remove(self.instance.uuid)
                if not tgs:
                    tgs = None
                service_inst.set_config("instance.nvl-targetGroups", tgs)

            # update list of registered targets
            registered_targets.pop(idx)

        # update target group config
        self.set_config("target_group.Targets", registered_targets)

        # reset availability zone
        if len(registered_targets) == 0:
            self.set_config("target_group.avz", None)

        return True

    def register_health_monitor(self, monitor):
        """Register health monitor with target group

        :param monitor: health monitor id
        :return: True
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # check health monitor exists
        hm_plugin: ApiNetworkHealthMonitor = self.controller.get_service_type_plugin(
            monitor, plugin_class=ApiNetworkHealthMonitor
        )

        # get health monitor service instance
        service_inst: ApiServiceInstance = hm_plugin.instance

        # check health monitor is already used
        _links, total = self.controller.get_links(type="tg-hm", end_service=service_inst.oid)
        if total != 0 and not hm_plugin.is_predefined():
            raise ApiManagerError(
                "Health monitor %s already registered with a target group. Deregister health "
                "monitor from target group before attaching it to new target group" % service_inst.uuid
            )

        # check target group has already a health monitor attached
        _links, total = self.controller.get_links(type="tg-hm", start_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError(
                "Target group %s already has a health monitor attached. Deregister attached "
                "health monitor from target group before attaching new health monitor" % service_inst.uuid
            )

        # add link to health monitor
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, service_inst.oid),
            type="tg-hm",
            end_service=service_inst.oid,
            attributes={},
        )

        # update target group configs
        self.set_config("target_group.HealthMonitor", service_inst.uuid)

        return True

    def deregister_health_monitor(self):
        """Deregister health monitor from target group

        :return: True
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # delete link between target group and health monitor
        links, total = self.controller.get_links(type="tg-hm", start_service=self.instance.oid)
        if total != 1:
            raise ApiManagerError("Cannot deregister health monitor from target group %s" % self.instance.uuid)
        links[0].expunge()

        # update target group configs
        self.set_config("target_group.HealthMonitor", None)

        return True
