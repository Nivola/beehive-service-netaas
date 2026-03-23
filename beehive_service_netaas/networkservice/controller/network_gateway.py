# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte


from __future__ import annotations
from copy import deepcopy
# from beecell.types.type_string import str2bool
from beehive.common.data import trace
from beehive.common.apimanager import ApiManagerError
from beehive_service.entity.service_instance import ApiServiceInstance
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
# from beehive_service.controller import ServiceController

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController

class ApiNetworkGateway(AsyncApiServiceTypePlugin):
    plugintype = "NetworkGateway"
    objname = "gateway"

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
        account_idx = controller.get_account_idx()
        instance_type_idx = controller.get_service_definition_idx(ApiNetworkGateway.plugintype)

        # get resources
        zones = []
        resources = []
        for entity in entities:
            entity.account = account_idx.get(str(entity.instance.account_id))

            # get instance type
            entity.instance_type = instance_type_idx.get(str(entity.instance.service_definition_id))

            # get resource
            if entity.instance.resource_uuid is not None:
                resources.append(entity.instance.resource_uuid)

        controller.logger.debug("+++++ customize_list - len(resources) %s" % len(resources))
        if len(resources) > 20:
            resources = []
        else:
            zones = []
        resources_list = ApiNetworkGateway(controller).list_resources(zones=zones, uuids=resources)
        resources_idx = {r["uuid"]: r for r in resources_list}

        # assign resources
        for entity in entities:
            entity.resource = resources_idx.get(entity.instance.resource_uuid)

        return entities

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.resource = self.get_resource()

    def get_vpcs(self):
        from beehive_service.plugins.computeservice.controller import ApiComputeVPC

        if self.resource is None:
            self.resource = self.get_resource()

        # get vpcs internal
        vpc_resources = dict_get(self.resource, "vpc.internals", default=[])

        vpcs = []
        for vpc_resource in vpc_resources:
            vpc_services, tot = self.controller.get_paginated_service_instances(
                resource_uuid=vpc_resource["uuid"],
                plugintype=ApiComputeVPC.plugintype,
                details=False,
                with_permtag=False,
            )
            if tot > 0:
                vpcs.append(vpc_services[0])

        return vpcs

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: "pending",
            SrvStatusType.BUILDING: "building",
            SrvStatusType.CREATED: "building",
            SrvStatusType.ACTIVE: "available",
            SrvStatusType.DELETED: "deregistered",
            SrvStatusType.DRAFT: "transient",
            SrvStatusType.ERROR: "error",
        }
        return mapping.get(state, "error")

    def vpc_state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: "pending",
            SrvStatusType.ACTIVE: "available",
            SrvStatusType.DELETED: "deregistered",
            SrvStatusType.DRAFT: "transient",
            SrvStatusType.ERROR: "error",
        }
        return mapping.get(state, "error")

    def aws_info(self):
        """Get info as required by aws api

        :param inst_service:
        :param resource:
        :param account_idx:
        :param instance_type_idx:
        :return:
        """
        instance_item = {}

        # get config
        config = self.get_config("gateway")
        if config is None:
            config = {}

        if self.resource is None:
            self.resource = {}

        bastion = self.resource.get("bastion", None)

        # get vpcs internal
        vpcs = self.get_vpcs()

        instance_item["ownerId"] = self.account.uuid
        instance_item["internetGatewayId"] = self.instance.uuid
        instance_item["nvl-state"] = self.state_mapping(self.instance.status)
        instance_item["attachmentSet"] = [
            {
                "VpcSecurityGroupMembership": {
                    "vpcId": vpc.uuid,
                    "state": self.vpc_state_mapping(vpc.status),
                    "nvl-vpcName": vpc.name,
                }
            }
            for vpc in vpcs
        ]

        instance_item["tagSet"] = []

        # custom params
        instance_item["nvl-name"] = self.instance.name
        instance_item["nvl-ownerAlias"] = self.account.name
        instance_item["nvl-external_ip_address"] = dict_get(self.resource, "external_ip_address.primary")
        instance_item["nvl-bastion"] = bastion

        return instance_item

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        # base quotas
        quotas = {
            "network.gateways": 1,
        }

        # get container
        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")

        # orchestrator_select_types_array = None
        # orchestrator_select_types: str = self.get_config("orchestrator_select_types")
        # if orchestrator_select_types is not None:
        #     orchestrator_select_types_array = orchestrator_select_types.split(",")

        uplink_vpc = self.get_config("uplink_vpc")
        transport_vpc = self.get_config("transport_vpc")
        primary_zone = self.get_config("primary_zone")
        primary_subnet = self.get_config("primary_subnet")
        primary_ip_address = self.get_config("primary_ip")
        secondary_zone = self.get_config("secondary_zone")
        secondary_subnet = self.get_config("secondary_subnet")
        secondary_ip_address = self.get_config("secondary_ip")
        admin_pwd = random_password(length=16, strong=True)
        dns = self.get_config("dns")
        dns_search = self.get_config("dns_search")
        flavor = self.get_config("flavor")
        volume_flavor = self.get_config("volume_flavor")

        # check quotas
        self.check_quotas(compute_zone, quotas)

        name = self.instance.name

        data = {
            "name": name,
            "desc": name,
            "orchestrator_tag": "default",
            # "orchestrator_select_types": orchestrator_select_types_array,
            "container": container_id,
            "compute_zone": compute_zone,
            "uplink_vpc": uplink_vpc,
            "transport_vpc": transport_vpc,
            "primary_zone": primary_zone,
            "primary_subnet": primary_subnet,
            "primary_ip_address": primary_ip_address,
            "admin_pwd": admin_pwd,
            "dns": dns,
            "dns_search": dns_search,
            "flavor": flavor,
            "volume_flavor": volume_flavor,
            "type": "vsphere",
            "host_group": "default",
        }
        if secondary_zone is not None:
            data.update(
                {
                    "secondary_zone": secondary_zone,
                    "secondary_subnet": secondary_subnet,
                    "secondary_ip_address": secondary_ip_address,
                }
            )
        params["resource_params"] = data
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params))) # aaa
        return params

    def pre_delete(self, **params):
        """Pre delete function. Use this function to manipulate and validate delete input params.

        :param params: input params
        :return: kvargs
        :raise ApiManagerError:
        """
        # print("+++++ pre_delete - self.instance.resource_uuid: %s" % self.instance.resource_uuid)
        if self.instance.resource_uuid is not None:
            if self.get_bastion_resource().get("name", None) is not None:
                raise ApiManagerError("Internet Gateway %s has an active bastion" % self.instance.uuid)

            if len(self.get_vpcs()) > 0:
                raise ApiManagerError("Internet Gateway %s has vpcs associated" % self.instance.uuid)

        return params

    #
    # action
    #
    def attach_vpc(self, vpc):
        """Attach vpc to gateway

        :param vpc: vpc id
        :return: True or False
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # check vpc not already attached
        vpc_service = self.controller.get_service_instance(vpc)
        if self.has_vpc(vpc_service.resource_uuid) is True:
            raise ApiManagerError("vpc %s already attached to gateway %s" % (vpc, self.instance.uuid))

        # task creation
        params = {
            "resource_params": {
                "action": "attach-vpc",
                "vpc": vpc_service.resource_uuid,
            }
        }
        self.action(**params)
        return True

    def detach_vpc(self, vpc):
        """Detach vpc from gateway

        :param vpc: vpc id
        :return: True or False
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # check vpc not already attached
        vpc_service = self.controller.get_service_instance(vpc)
        if self.has_vpc(vpc_service.resource_uuid) is False:
            raise ApiManagerError("vpc %s is not attached to gateway %s" % (vpc, self.instance.uuid))

        # task creation
        params = {
            "resource_params": {
                "action": "detach-vpc",
                "vpc": vpc_service.resource_uuid,
            }
        }
        self.action(**params)
        return True

    def get_bastion(self):
        """Create gateway bastion

        :return: True or False
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "use",
        )

        bastion = self.get_bastion_resource()
        res = {
            "nvl_name": bastion.get("name", None),
            "ncl_state": bastion.get("state", None),
        }
        return res

    def create_bastion(self):
        """Create gateway bastion

        :return: True or False
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # check bastion does not already exist
        bastion = self.get_bastion_resource()
        if bastion.get("name", None) is not None:
            raise ApiManagerError("Internet Gateway %s already have a bastion" % self.instance.uuid)

        # task creation
        params = {"resource_params": {"action": "create_bastion"}}
        self.action(**params)
        return True

    def delete_bastion(self):
        """Delete gateway bastion

        :return: True or False
        """
        # checks authorization
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            self.instance.objid,
            "update",
        )

        # check bastion does not already exist
        bastion = self.get_bastion_resource()
        if bastion.get("name", None) is None:
            raise ApiManagerError("Internet Gateway %s does not have a bastion" % self.instance.uuid)

        # task creation
        params = {"resource_params": {"action": "delete_bastion"}}
        self.action(**params)
        return True

    #
    # resource client method
    #
    @trace(op="view")
    def has_vpc(self, vpc_resource_uuid):
        """Check vpc already attached

        :return: True if vpc is attached
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        resource = self.get_resource()
        vpc_resources = dict_get(resource, "vpc.internals", default=[])
        for vpc_resource in vpc_resources:
            if vpc_resource_uuid == vpc_resource["uuid"]:
                return True
        return False

    @trace(op="view")
    def get_resource(self):
        """Get resource info

        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        try:
            uri = "/v1.0/nrs/provider/gateways/%s" % self.instance.resource_uuid
            instance = self.controller.api_client.admin_request("resource", uri, "get", data="").get("gateway")
            self.logger.debug("Get gateway resource: %s" % truncate(instance))
        except Exception:
            instance = {}
        return instance

    @trace(op="view")
    def get_bastion_resource(self):
        """Get bastion resource info

        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        uri = "/v1.0/nrs/provider/gateways/%s/bastion" % self.instance.resource_uuid
        instance = self.controller.api_client.admin_request("resource", uri, "get", data="").get("bastion")
        self.logger.debug("Get gateway bastion resource: %s" % truncate(instance))
        return instance

    @trace(op="view")
    def list_resources(self, zones=None, uuids=None, tags=None, page=0, size=100):
        """Get resource info

        :return: Dictionary with resources info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        if zones is None:
            zones = []
        if uuids is None:
            uuids = []
        if tags is None:
            tags = []
        data = {"size": size, "page": page}
        if len(zones) > 0:
            data["parent_list"] = ",".join(zones)
        if len(uuids) > 0:
            data["uuids"] = ",".join(uuids)
        if len(tags) > 0:
            data["tags"] = ",".join(tags)

        instances = self.controller.api_client.admin_request(
            "resource", "/v1.0/nrs/provider/gateways", "get", data=urlencode(data)
        ).get("gateways", [])
        self.controller.logger.debug("Get gateway resources: %s" % truncate(instances))
        return instances

    @trace(op="insert")
    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {"gateway": args[0]}
        try:
            uri = "/v1.0/nrs/provider/gateways"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create gateway resource: %s" % uuid)
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
            self.controller.logger.debug("Update gateway resource: %s" % uuid)

        # set default routes
        data = {"role": "default"}
        try:
            uri = "/v1.0/nrs/provider/gateways/%s/route/default" % uuid
            res = self.controller.api_client.admin_request("resource", uri, "put", data=data)
            taskid = res.get("taskid", None)
            self.logger.debug("set gateway %s default routes - start" % uuid)
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
            self.controller.logger.debug("set gateway %s default routes" % uuid)

        return uuid

    def action_resource(self, task, *args, **kvargs):
        """Send action to resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # create new rules
        action = kvargs.get("action", None)

        if action == "attach-vpc":
            vpc = kvargs.get("vpc")
            self.__attach_vpc_resource(task, vpc)
        elif action == "detach-vpc":
            vpc = kvargs.get("vpc")
            self.__detach_vpc_resource(task, vpc)
        elif action == "create_bastion":
            self.__create_bastion(task)
        elif action == "delete_bastion":
            self.__delete_bastion(task)

        return True

    def __attach_vpc_resource(self, task, vpc):
        """attach vp to gateway. Api call

        :param task: celery task
        :param vpc: vpc resource uuid
        :return:
        """
        uuid = self.instance.resource_uuid
        try:
            data = {"vpc": vpc}
            uri = "/v1.0/nrs/provider/gateways/%s/vpc" % uuid
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            taskid = res.get("taskid", None)
            self.logger.debug("attach vpc %s to gateway %s - start" % (vpc, uuid))
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
            self.controller.logger.debug("attach vpc %s to gateway %s" % (vpc, uuid))

    def __detach_vpc_resource(self, task, vpc):
        """detach vp from gateway. Api call

        :param task: celery task
        :param vpc: vpc resource uuid
        :return:
        """
        uuid = self.instance.resource_uuid
        try:
            data = {"vpc": vpc}
            uri = "/v1.0/nrs/provider/gateways/%s/vpc" % uuid
            res = self.controller.api_client.admin_request("resource", uri, "delete", data=data)
            taskid = res.get("taskid", None)
            self.logger.debug("detach vpc %s from gateway %s - start" % (vpc, uuid))
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
            self.controller.logger.debug("detach vpc %s from gateway %s" % (vpc, uuid))

    def __create_bastion(self, task):
        """create gateway bastion. Api call

        :param task: celery task
        :return:
        """
        account = self.get_account()

        # get container
        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")
        primary_zone = self.get_config("primary_zone")
        bastion_conf = self.get_config("bastion")
        flavor = bastion_conf.get("flavor")
        volume_flavor = bastion_conf.get("volume_flavor")
        image = bastion_conf.get("image")
        key_name = bastion_conf.get("key_name")
        acls = [{"subnet": s} for s in bastion_conf.get("acls").split(",")]

        # orchestrator_select_types_array = None
        # orchestrator_select_types: str = self.get_config("orchestrator_select_types")
        # if orchestrator_select_types is not None:
        #     orchestrator_select_types_array = orchestrator_select_types.split(",")

        name = "%s-bastion-01" % account.name
        desc = "bastion %s" % account.name

        data = {
            "name": name,
            "desc": desc,
            "orchestrator_tag": "default",
            # "orchestrator_select_types": orchestrator_select_types_array,
            "container": container_id,
            "compute_zone": compute_zone,
            "availability_zone": primary_zone,
            "host_group": "default",
            "acl": acls,
            "flavor": flavor,
            "volume_flavor": volume_flavor,
            "image": image,
            "key_name": key_name,
        }

        uuid = self.instance.resource_uuid
        try:
            data = {"bastion": data}
            self.logger.debug("create gateway %s bastion - data: %s" % (uuid, data))
            uri = "/v1.0/nrs/provider/bastions"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            taskid = res.get("taskid", None)
            self.logger.debug("create gateway %s bastion - start" % uuid)
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
            self.wait_for_task(taskid, delta=2, maxtime=3600, task=task)
            self.controller.logger.debug("create gateway %s bastion - start" % uuid)

    def __delete_bastion(self, task):
        """Delete gateway bastion. Api call

        :param task: celery task
        :return:
        """
        uuid = self.instance.resource_uuid
        bastion_uuid = self.get_bastion_resource().get("uuid")
        try:
            uri = "/v1.0/nrs/provider/bastions/%s" % bastion_uuid
            res = self.controller.api_client.admin_request("resource", uri, "delete", data="")
            taskid = res.get("taskid", None)
            self.logger.debug("delete gateway %s bastion - start" % uuid)
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
            self.wait_for_task(taskid, delta=2, maxtime=3600, task=task)
            self.controller.logger.debug("delete gateway %s bastion - start" % uuid)

