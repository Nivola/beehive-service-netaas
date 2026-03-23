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
from .network_listener import ApiNetworkListener
from .network_target_group import ApiNetworkTargetGroup
from .network_gateway import ApiNetworkGateway
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController
    from .network_health_monitor import ApiNetworkHealthMonitor


class ApiNetworkLoadBalancer(AsyncApiServiceTypePlugin):
    plugintype = "NetworkLoadBalancer"
    objname = "load_balancer"
    class_child_classes = []

    def __init__(self, *args, **kvargs):
        """ """
        ApiServiceTypePlugin.__init__(self, *args, **kvargs)

        self.child_classes = self.class_child_classes

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
    def customize_list(controller: ServiceController, entities, *args, **kvargs):
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
        self.controller: ServiceController
        self.account = self.controller.get_account(str(self.instance.account_id))
        if self.resource_uuid is not None:
            try:
                self.resource = self.get_resource()
            except Exception:
                self.resource = None

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

    @trace(op="view")
    def get_resource(self):
        """Get resource info

        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        try:
            uri = "/v1.0/nrs/provider/loadbalancers/%s" % self.instance.resource_uuid
            instance = self.controller.api_client.admin_request("resource", uri, "get", data="").get("load_balancer")
            self.logger.debug("Get load balancer resource: %s" % truncate(instance))
        except Exception:
            instance = {}
        return instance

    def get_vip(self):
        """Get load balancer frontend IP address

        :rtype: string, bool
        """
        if self.resource is None:
            self.resource = self.get_resource()

        vip = dict_get(self.resource, "attributes.vip")
        is_static = dict_get(self.resource, "attributes.is_static")
        return vip, is_static

    def __get_object_info(self, oid, plugin_class):
        try:
            type_plugin = self.controller.get_service_type_plugin(oid, plugin_class=plugin_class)
            info = type_plugin.aws_info()
        except Exception:
            info = {}
        return info

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.account is None:
            self.post_get()

        # get config
        config = self.get_config("load_balancer")
        if config is None:
            config = {}

        if self.resource is None:
            self.resource = {}

        # get load balancer virtual ip
        vip, is_static = self.get_vip()

        instance_item = {
            "ownerId": self.account.uuid,
            "nvl-ownerAlias": self.account.name,
            "loadBalancerId": self.instance.uuid,
            "name": self.instance.name,
            "state": self.state_mapping(self.instance.status),
            "runstate": self.resource.get("runstate"),
            "template": config.get("Template"),
            "deployment_env": config.get("DeploymentEnvironment"),
            "virtualIP": vip,
            "isVIPStatic": is_static,
            "protocol": config.get("Protocol"),
            "port": config.get("Port"),
            "maxConn": config.get("MaxConnections"),
            "maxConnRate": config.get("MaxConnectionRate"),
            "nvl-resourceId": self.instance.resource_uuid,
            "attachmentSet": {},
            "tagSet": [],
        }

        # get listener info
        d = {"Listener": self.__get_object_info(config.get("Listener"), ApiNetworkListener)}
        instance_item["attachmentSet"].update(d)

        # get target group info
        d = {"TargetGroup": self.__get_object_info(config.get("TargetGroup"), ApiNetworkTargetGroup)}
        instance_item["attachmentSet"].update(d)

        return instance_item

    @staticmethod
    def __validate_params(lb_data=None, li_data=None, tg_data=None, hm_data=None):
        protocol = ""
        if lb_data is not None:
            protocol = lb_data.get("Protocol")
        traffic_type = ""
        if li_data is not None:
            traffic_type = li_data.get("trafficType")
        if (protocol == "http" and ("https" in traffic_type or "ssl" in traffic_type)) or (
            protocol == "https" and traffic_type == "http"
        ):
            raise ApiManagerError(
                "Parameters inconsistency detected: protocol: %s, traffic type: %s" % (protocol, traffic_type)
            )
        # add other checks...

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        # base quotas
        quotas = {"network.loadbalancers": 1}

        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")
        network_appliance = self.get_config("network_appliance")
        selection_criteria = network_appliance.get("selection_criteria")
        is_private = self.get_config("is_private")
        site_networks = self.get_config("site_networks")
        lb_config = self.get_config("load_balancer")
        protocol = lb_config.get("Protocol")
        port = lb_config.get("Port")
        listener_id = lb_config.get("Listener")
        target_group_id = lb_config.get("TargetGroup")

        controller = self.controller

        # get listener
        listener: ApiServiceInstance = controller.get_service_instance(listener_id)
        listener_plugin: ApiNetworkListener = listener.get_service_type_plugin()
        listener_info = listener_plugin.aws_info()
        li_predefined = dict_get(listener_info, "attachmentSet.Listener.predefined")
        if li_predefined is False:
            _links, total = controller.get_links(type="lb-li", end_service=listener.oid)
            if total != 0:
                raise ApiManagerError(
                    "Listener %s is registered with another load balancer and cannot be reused" % listener.uuid
                )

        # get target group
        target_group: ApiServiceInstance = controller.get_service_instance(target_group_id)
        target_group_plugin: ApiNetworkTargetGroup = target_group.get_service_type_plugin()
        target_group_info = target_group_plugin.aws_info()
        _links, total = controller.get_links(type="lb-tg", end_service=target_group.oid)
        if total != 0:
            raise ApiManagerError(
                "Target group %s is registered with another load balancer and cannot be reused" % target_group.uuid
            )

        # get health monitor if exists
        health_monitor_info = None
        health_monitor_id = dict_get(target_group_info, "attachmentSet.HealthMonitor.healthMonitorId")
        if health_monitor_id is not None:
            health_monitor_inst: ApiServiceInstance = controller.get_service_instance(health_monitor_id)
            health_monitor_plugin: ApiNetworkHealthMonitor = health_monitor_inst.get_service_type_plugin()
            health_monitor_info = health_monitor_plugin.aws_info()

        # check consistency among load balancer, listener, target group and health monitor parameters
        self.__validate_params(
            lb_data=lb_config, li_data=listener_info, tg_data=target_group_info, hm_data=health_monitor_info
        )

        # get site from first target.
        # Note: all targets belong to the same site by design
        targets = dict_get(target_group_info, "attachmentSet.TargetSet.Targets")
        if len(targets) == 0:
            raise ApiManagerError(
                "Empty target group. Register at least a target with target group before " "creating load balancer"
            )
        site_name = dict_get(targets[0], "site.name")
        site_uuid = dict_get(targets[0], "site.uuid")
        self.logger.debug("Load balancer site: %s" % site_name)

        # get targets
        target_lst = []
        for target in targets:
            target_name = target.get("name")
            target_resource_uuid = target.get("resource_uuid")
            target_lb_port = target.get("lb_port")
            if target_lb_port is None:
                target_lb_port = port
            target_hm_port = target.get("hm_port")
            if target_hm_port is None:
                target_hm_port = target_lb_port
            target_lst.append(
                {
                    "name": target_name,
                    "resource_uuid": target_resource_uuid,
                    "lb_port": target_lb_port,
                    "hm_port": target_hm_port,
                }
            )

        # check availability zone status
        if self.is_availability_zone_active(compute_zone, site_name) is False:
            raise ApiManagerError("Availability zone %s is not in status available" % site_name)

        # check quotas
        self.check_quotas(compute_zone, quotas)

        account = self.instance.get_account()
        full_account_name = account.get_triplet_name()
        description = dumps({"account": full_account_name})

        data = {
            "name": self.instance.name,
            "desc": description,
            "orchestrator_tag": "default",
            "container": container_id,
            "compute_zone": compute_zone,
            "site": site_uuid,
            "is_private": is_private,
            "selection_criteria": selection_criteria,
            "lb_configs": {
                "protocol": protocol,
                "port": port,
                "static_ip": lb_config.get("StaticIP"),
                "max_conn": lb_config.get("MaxConnections"),
                "max_conn_rate": lb_config.get("MaxConnectionRate"),
                "deployment_env": lb_config.get("DeploymentEnvironment"),
            },
        }

        if is_private:
            # get account
            from beehive_service.controller.api_account import ApiAccount

            account: ApiAccount = self.get_account()

            # get internet gateway plugin type, must be unique
            res, _tot = controller.get_service_type_plugins(
                account_id=account.oid,
                plugintype=ApiNetworkGateway.plugintype,
                size=-1,
            )
            if len(res) != 1:
                raise ApiManagerError(f"Internet gateway for account {account.uuid} not found")
            igw = res[0]

            # get internet gateway instance
            igw_inst: ApiServiceInstance = igw.instance

            # get internet gateway resource uuid
            gw_res_uuid = igw_inst.resource_uuid
            data["gateway"] = gw_res_uuid

            # get vpc resource uuid
            vpcs = igw.get_vpcs()
            vpc = vpcs[0]
            data["vpc"] = vpc.resource_uuid
        else:
            # select site network
            site_network = site_networks.get(site_name)
            data["site_network"] = site_network

        data["lb_configs"].update(
            {
                "listener": {
                    "name": listener_info.get("name"),
                    "desc": listener_info.get("desc"),
                    "traffic_type": listener_info.get("trafficType"),
                    "persistence": {
                        "method": dict_get(listener_info, "persistence.method"),
                        "cookie_name": dict_get(listener_info, "persistence.cookieName"),
                        "cookie_mode": dict_get(listener_info, "persistence.cookieMode"),
                        "expire_time": dict_get(listener_info, "persistence.expirationTime"),
                    },
                    "insert_x_forwarded_for": listener_info.get("insertXForwardedFor"),
                    "url_redirect": listener_info.get("urlRedirect"),
                    "predefined": listener_info.get("predefined"),
                    "ext_name": listener_info.get("ext_name"),
                }
            }
        )

        data["lb_configs"].update(
            {
                "target_group": {
                    "name": target_group_info.get("name"),
                    "desc": target_group_info.get("desc"),
                    "balancing_algorithm": target_group_info.get("balancingAlgorithm"),
                    "target_type": target_group_info.get("targetType"),
                    "targets": target_lst,
                }
            }
        )

        if health_monitor_id is not None:
            data["lb_configs"].update(
                {
                    "health_monitor": {
                        "name": health_monitor_info.get("name"),
                        "protocol": health_monitor_info.get("protocol"),
                        "interval": health_monitor_info.get("interval"),
                        "timeout": health_monitor_info.get("timeout"),
                        "max_retries": health_monitor_info.get("maxRetries"),
                        "method": health_monitor_info.get("method"),
                        "request_uri": health_monitor_info.get("requestURI"),
                        "expected": health_monitor_info.get("expected"),
                        "predefined": health_monitor_info.get("predefined"),
                        "ext_name": health_monitor_info.get("ext_name"),
                    }
                }
            )

        params["resource_params"] = data
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    def post_create(self, **params):
        """Post create function. Use this after service creation
        Extend this function to execute some operation after entity was created.

        :param params: input params
        :return: None
        :raise ApiManagerError:
        """
        li_id = self.get_config("load_balancer.Listener")
        tg_id = self.get_config("load_balancer.TargetGroup")

        # self.controller: ServiceController
        listener: ApiServiceInstance = self.controller.get_service_instance(li_id)
        target_group: ApiServiceInstance = self.controller.get_service_instance(tg_id)

        # link load balancer to listener
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, listener.oid),
            type="lb-li",
            end_service=listener.oid,
            attributes={},
        )

        # link load balancer to target group
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, target_group.oid),
            type="lb-tg",
            end_service=target_group.oid,
            attributes={},
        )

        return None

    def pre_import(self, **params):
        """Check input params before resource import. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        Service instance config is populated with: owner_id, service_definition_id, computeZone

        :param params: input params
        :param params.id: inst.oid,
        :param params.uuid: inst.uuid,
        :param params.objid: inst.objid,
        :param params.name: name,
        :param params.desc: desc,
        :param params.attribute: None,
        :param params.tags: None,
        :param params.resource_id: resource_id
        :return: resource input params
        :raise ApiManagerError:
        """
        self.instance.set_config("load_balancer.Template", params.get("Template"))
        self.instance.set_config("load_balancer.DeploymentEnvironment", params.get("DeploymentEnvironment"))
        self.instance.set_config("load_balancer.Protocol", params.get("Protocol"))
        self.instance.set_config("load_balancer.Port", params.get("Port"))
        self.instance.set_config("load_balancer.MaxConnections", params.get("MaxConnections"))
        self.instance.set_config("load_balancer.MaxConnectionRate", params.get("MaxConnectionRate"))
        self.instance.set_config("load_balancer.Listener", params.get("Listener"))
        self.instance.set_config("load_balancer.TargetGroup", params.get("TargetGroup"))

        return params

    def post_import(self, **params):
        """Post import function. Use this after service creation.
        Extend this function to execute some operation after entity was created.

        :param params: input params
        :return: None
        :raise ApiManagerError:
        """
        li_id = params.get("Listener")
        tg_id = params.get("TargetGroup")

        listener: ApiServiceInstance = self.controller.get_service_instance(li_id)
        target_group: ApiServiceInstance = self.controller.get_service_instance(tg_id)

        # link load balancer to listener
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, listener.oid),
            type="lb-li",
            end_service=li_id,
            attributes={},
        )

        # link load balancer to target group
        self.add_link(
            name="link-%s-%s" % (self.instance.oid, target_group.oid),
            type="lb-tg",
            end_service=tg_id,
            attributes={},
        )

        return None

    def pre_update(self, **params):
        """Pre update function. This function is used in update method.

        :param params: input key=value params
        :return: params
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        desc = params.pop("Description", None)
        proto = params.pop("Protocol", None)
        port = params.pop("Port", None)
        max_conn = params.pop("MaxConnections", None)
        max_conn_rate = params.pop("MaxConnectionRate", None)

        lb_config = self.get_config("load_balancer")
        listener_id = lb_config.get("Listener")
        target_group_id = lb_config.get("TargetGroup")

        # controller = self.controller

        # get listener and check it is active
        listener_inst: ApiServiceInstance = self.controller.get_service_instance(listener_id)
        listener_plugin: ApiNetworkListener = listener_inst.get_service_type_plugin()
        listener_info = listener_plugin.aws_info()

        # get target group and check it is active
        target_group_inst: ApiServiceInstance = self.controller.get_service_instance(target_group_id)
        target_group_plugin: ApiNetworkTargetGroup = target_group_inst.get_service_type_plugin()
        target_group_info = target_group_plugin.aws_info()

        # get health monitor if exists
        health_monitor_id = dict_get(target_group_info, "attachmentSet.HealthMonitor.healthMonitorId")
        health_monitor_info = None
        if health_monitor_id is not None:
            health_monitor_inst: ApiServiceInstance = self.controller.get_service_instance(health_monitor_id)
            health_monitor_plugin: ApiNetworkHealthMonitor = health_monitor_inst.get_service_type_plugin()
            health_monitor_info = health_monitor_plugin.aws_info()

        # check params consistency
        self.__validate_params(lb_config, listener_info, target_group_info, health_monitor_info)

        data = {
            "lb_configs": {
                "description": lb_config.get("Description", desc),
                "protocol": lb_config.get("Protocol", proto),
                "port": lb_config.get("Port", port),
                "max_conn": lb_config.get("MaxConnections", max_conn),
                "max_conn_rate": lb_config.get("MaxConnectionRate", max_conn_rate),
            }
        }

        data["lb_configs"].update(
            {
                "listener": {
                    "desc": listener_info.get("desc"),
                    "traffic_type": listener_info.get("trafficType"),
                    "persistence": {
                        "method": dict_get(listener_info, "persistence.method"),
                        "cookie_name": dict_get(listener_info, "persistence.cookieName"),
                        "cookie_mode": dict_get(listener_info, "persistence.cookieMode"),
                        "expire_time": dict_get(listener_info, "persistence.expirationTime"),
                    },
                    "insert_x_forwarded_for": listener_info.get("insertXForwardedFor"),
                    "url_redirect": listener_info.get("urlRedirect"),
                    "predefined": listener_info.get("predefined"),
                    "ext_name": listener_info.get("ext_name"),
                }
            }
        )

        # get target group availability zone
        targets = dict_get(target_group_info, "attachmentSet.TargetSet.Targets")
        target_group_avz = None
        if len(targets) > 0:
            target_group_avz = dict_get(targets[0], "avz.uuid")
        self.logger.debug(
            "Target group %s availability zone: %s" % (target_group_info.get("targetGroupId"), target_group_avz)
        )

        compute_zone = self.get_config("computeZone")
        site_id = dict_get(self.resource, "attributes.site")
        avz = self.get_resource_availability_zone_by_site(compute_zone, site_id)

        # check consistency between load balancer availability zone and target group availability zone
        if target_group_avz is not None and avz.get("uuid") != target_group_avz:
            raise ApiManagerError("Availability zone mismatch between load balancer and targets to be balanced")

        # get targets
        target_lst = []
        for target in targets:
            target_name = target.get("name")
            target_resource_uuid = target.get("resource_uuid")
            target_lb_port = target.get("lb_port")
            if target_lb_port is None:
                target_lb_port = lb_config.get("Port")
            target_hm_port = target.get("hm_port")
            if target_hm_port is None:
                target_hm_port = target_lb_port
            target_lst.append(
                {
                    "name": target_name,
                    "resource_uuid": target_resource_uuid,
                    "lb_port": target_lb_port,
                    "hm_port": target_hm_port,
                }
            )

        data["lb_configs"].update(
            {
                "target_group": {
                    "desc": target_group_info.get("desc"),
                    "balancing_algorithm": target_group_info.get("balancingAlgorithm"),
                    "target_type": target_group_info.get("targetType"),
                    "targets": target_lst,
                }
            }
        )

        # update hm attributes only if hm is configured
        if health_monitor_info is not None:
            data["lb_configs"].update(
                {
                    "health_monitor": {
                        "protocol": health_monitor_info.get("protocol"),
                        "interval": health_monitor_info.get("interval"),
                        "timeout": health_monitor_info.get("timeout"),
                        "max_retries": health_monitor_info.get("maxRetries"),
                        "method": health_monitor_info.get("method"),
                        "request_uri": health_monitor_info.get("requestURI"),
                        "expected": health_monitor_info.get("expected"),
                        "predefined": health_monitor_info.get("predefined"),
                        "ext_name": health_monitor_info.get("ext_name"),
                    }
                }
            )

        params["resource_params"] = data
        self.logger.debug("Pre update params: %s" % obscure_data(deepcopy(params)))
        return params

    def pre_delete(self, **params):
        """Pre delete function. Use this function to manipulate and validate delete input params.

        :param params: input params
        :param params.no_linked_objs: to avoid deleting listener and target group linked to load balancer
        :return: kvargs
        :raise ApiManagerError:
        """
        no_linked_objs = params.get("no_linked_objs")
        lb_config = self.get_config("load_balancer")
        li_id = lb_config.get("Listener")
        tg_id = lb_config.get("TargetGroup")

        # controller: ServiceController = self.controller

        try:
            # remove link to listener
            links, _tot = self.controller.get_links(start_service=self.instance.oid, type="lb-li")
            links[0].expunge()
            if not no_linked_objs:
                # delete listener instance
                type_plugin = self.controller.get_service_type_plugin(li_id)
                type_plugin.delete()
        except Exception:
            # go ahead anyway
            pass

        try:
            # remove link to target group
            links, _tot = self.controller.get_links(start_service=self.instance.oid, type="lb-tg")
            links[0].expunge()
            if not no_linked_objs:
                # delete target group instance
                type_plugin = self.controller.get_service_type_plugin(tg_id)
                type_plugin.delete()
        except Exception:
            # go ahead anyway
            pass

        return params

    def start(self):
        """Enable load balancer

        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        params = {"resource_params": {"action": "start", "args": True}}
        self.action(**params)
        return True

    def stop(self):
        """Disable load balancer

        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        params = {"resource_params": {"action": "stop", "args": True}}
        self.action(**params)
        return True

    #
    # Resource API calls
    #
    @trace(op="insert")
    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: resource uuid
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {"load_balancer": args[0]}
        try:
            uri = "/v1.0/nrs/provider/loadbalancers"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create load balancer resource: %s" % uuid)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        # set resource uuid
        if uuid is not None and taskid is not None:
            self.set_resource(uuid)
            self.update_status(SrvStatusType.PENDING)
            self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
            self.update_status(SrvStatusType.CREATED)
            self.controller.logger.debug("Update load balancer resource: %s" % uuid)

        return uuid

    def update_resource(self, task, *args, **kvargs):
        """Update resource

        :param task: celery task which is calling the method
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        try:
            if len(kvargs.keys()) > 0:
                data = {"load_balancer": kvargs}
                uri = "/v1.0/nrs/provider/loadbalancers/%s" % self.instance.resource_uuid
                res = self.controller.api_client.admin_request("resource", uri, "put", data=data)
                taskid = res.get("taskid", None)
                if taskid is not None:
                    self.wait_for_task(taskid, delta=4, maxtime=600, task=task)
                self.logger.debug("Update load balancer resources: %s" % res)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.instance.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        return True

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        return ApiServiceTypePlugin.delete_resource(self, task, *args, **kvargs)

    def action_resource(self, task, *args, **kvargs):
        """Send action to resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        action = kvargs.pop("action", None)
        params = kvargs.pop("args", None)
        uuid = self.instance.resource_uuid
        try:
            data = {"action": {action: params}}
            uri = "/v1.0/nrs/provider/loadbalancers/%s/action" % uuid
            res = self.controller.api_client.admin_request("resource", uri, "put", data=data)
            taskid = res.get("taskid", None)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        # set resource uuid
        if taskid is not None:
            self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
        self.logger.debug("Send action '%s' to load balancer resources: %s" % (action, res))

        return True

    #
    # Another way to implement action_resource method
    #
    # def action_resource(self, task, *args, **kvargs):
    #     """Send action to resource
    #
    #     :param task: celery task reference
    #     :param args: custom positional args
    #     :param kvargs: custom key=value args
    #     :return: True
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     action = kvargs.get('action', None)
    #
    #     if action == 'start':
    #         self.__enable_load_balancer_resource(task)
    #     elif action == 'stop':
    #         self.__disable_load_balancer_resource(task)
    #     elif action == 'some_other_action':
    #         pass
    #
    #     return True
    #
    # def __enable_load_balancer_resource(self, task):
    #     """Enable load balancer. Api call
    #
    #     :param task: celery task
    #     :return:
    #     """
    #     uuid = self.instance.resource_uuid
    #     try:
    #         data = {'action': 'start'}
    #         uri = '/v1.0/nrs/provider/loadbalancers/%s/action' % uuid
    #         res = self.controller.api_client.admin_request('resource', uri, 'put', data=data)
    #         taskid = res.get('taskid', None)
    #         self.logger.debug('Enable load balancer %s - start' % uuid)
    #     except ApiManagerError as ex:
    #         self.logger.error(ex, exc_info=True)
    #         self.update_status(SrvStatusType.ERROR, error=ex.value)
    #         raise
    #     except Exception as ex:
    #         self.logger.error(ex, exc_info=True)
    #         self.update_status(SrvStatusType.ERROR, error=str(ex))
    #         raise ApiManagerError(str(ex))
    #
    #     # set resource uuid
    #     if taskid is not None:
    #         self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
    #         self.controller.logger.debug('Enable load balancer %s' % uuid)
    #
    # def __disable_load_balancer_resource(self, task):
    #     """Disable load balancer. Api call
    #
    #     :param task: celery task
    #     :return:
    #     """
