# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2024 CSI-Piemonte

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
from six.moves.urllib.parse import urlencode
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

from typing import List
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress


class ApiNetworkService(ApiServiceTypeContainer):
    objuri = "networkservice"
    objname = "networkservice"
    objdesc = "NetworkService"
    plugintype = "NetworkService"

    def __init__(self, *args, **kvargs):
        """ """
        ApiServiceTypeContainer.__init__(self, *args, **kvargs)
        self.flag_async = True

        self.child_classes = [
            ApiNetworkGateway,
            ApiNetworkVpc,
            ApiNetworkHealthMonitor,
            ApiNetworkTargetGroup,
            ApiNetworkListener,
            ApiNetworkLoadBalancer,
            # ApiNetworkSubnet,
            # ApiNetworkSecurityGroup
        ]

    def info(self):
        """Get object info

        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = ApiServiceTypeContainer.info(self)
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
        account_idx = controller.get_account_idx()
        instance_type_idx = controller.get_service_definition_idx(ApiNetworkService.plugintype)

        # get resources
        # zones = []
        resources = []
        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.account = account_idx.get(account_id)
            entity.instance_type = instance_type_idx.get(str(entity.instance.service_definition_id))
            if entity.instance.resource_uuid is not None:
                resources.append(entity.instance.resource_uuid)

        resources_list = ApiNetworkService(controller).list_resources(uuids=resources)
        resources_idx = {r["uuid"]: r for r in resources_list}

        # assign resources
        for entity in entities:
            entity.resource = resources_idx.get(entity.instance.resource_uuid)

        return entities

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        compute_services, tot = self.controller.get_paginated_service_instances(
            plugintype="ComputeService",
            account_id=self.instance.account_id,
            filter_expired=False,
        )
        if tot == 0:
            raise ApiManagerError("Some service dependency does not exist")

        compute_service = compute_services[0]

        if compute_service.is_active() is False:
            raise ApiManagerError("Some service dependency are not in the correct status")

        # set resource uuid
        self.set_resource(compute_service.resource_uuid)

        params["resource_params"] = {}
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: "pending",
            SrvStatusType.ACTIVE: "available",
            SrvStatusType.DELETED: "deregistered",
            SrvStatusType.DRAFT: "trasient",
            SrvStatusType.ERROR: "error",
        }
        return mapping.get(state, "error")

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.resource is None:
            self.resource = {}

        instance_item = {}
        instance_item["id"] = self.instance.uuid
        instance_item["name"] = self.instance.name
        instance_item["creationDate"] = format_date(self.instance.model.creation_date)
        instance_item["description"] = self.instance.desc
        instance_item["state"] = self.state_mapping(self.instance.status)
        instance_item["owner"] = self.account.uuid
        instance_item["owner_name"] = self.account.name
        instance_item["template"] = self.instance_type.uuid
        instance_item["template_name"] = self.instance_type.name
        instance_item["stateReason"] = {"code": None, "message": None}
        if self.instance.status == "ERROR":
            instance_item["stateReason"] = {
                "code": 400,
                "message": self.instance.last_error,
            }
        instance_item["resource_uuid"] = self.instance.resource_uuid

        return instance_item

    def aws_get_attributes(self):
        """Get account attributes like quotas

        :return:
        """
        if self.resource is None:
            self.resource = {}
        attributes = []

        for quota in self.get_resource_quotas():
            name = quota.get("quota")
            if name.find("network") == 0:
                name = name.replace("network.", "")
                attributes_item = {
                    "attributeName": "%s [%s]" % (name, quota.get("unit")),
                    "attributeValueSet": [
                        {
                            "item": {
                                "attributeValue": quota.get("value"),
                                "nvl-attributeUsed": quota.get("allocated"),
                            }
                        }
                    ],
                }
                attributes.append(attributes_item)

        return attributes

    def set_attributes(self, quotas):
        """Set service quotas

        :param quotas: dict with quotas to set
        :return: Dictionary with quotas.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {}
        for quota, value in quotas.items():
            data["network.%s" % quota] = value

        res = self.set_resource_quotas(None, data)
        return res

    def get_attributes(self, prefix="network"):
        return self.get_container_attributes(prefix=prefix)

    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        self.update_status(SrvStatusType.PENDING)
        quotas = self.get_config("quota")
        self.set_resource_quotas(task, quotas)

        # update service status
        self.update_status(SrvStatusType.CREATED)
        self.logger.debug("Update network instance resources: %s" % self.instance.resource_uuid)

        return self.instance.resource_uuid

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource do nothing. Compute zone is owned by ComputeService

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        return True


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

        if len(resources) > 3:
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

        bastion = self.resource.get("bastion", {})

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
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))
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


class ApiNetworkClientVpn(AsyncApiServiceTypePlugin):
    plugintype = "NetworkClientVpn"
    objname = "clientvpn"

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

    # @staticmethod
    # def customize_list(controller, entities, *args, **kvargs):
    #     """Post list function. Extend this function to execute some operation after entity was created. Used only for
    #     synchronous creation.
    #
    #     :param controller: controller instance
    #     :param entities: list of entities
    #     :param args: custom params
    #     :param kvargs: custom params
    #     :return: None
    #     :raise ApiManagerError:
    #     """
    #     account_idx = controller.get_account_idx()
    #     # vpc_idx = controller.get_service_instance_idx(ApiNetworkVpc.plugintype, index_key='')
    #     instance_type_idx = controller.get_service_definition_idx(ApiNetworkGateway.plugintype)
    #
    #     # get resources
    #     zones = []
    #     resources = []
    #     for entity in entities:
    #         entity.account = account_idx.get(str(entity.instance.account_id))
    #
    #         # get instance type
    #         entity.instance_type = instance_type_idx.get(str(entity.instance.service_definition_id))
    #
    #         # get resource
    #         if entity.instance.resource_uuid is not None:
    #             resources.append(entity.instance.resource_uuid)
    #
    #     if len(resources) > 3:
    #         resources = []
    #     else:
    #         zones = []
    #     resources_list = ApiNetworkGateway(controller).list_resources(zones=zones, uuids=resources)
    #     resources_idx = {r['uuid']: r for r in resources_list}
    #
    #     # assign resources
    #     for entity in entities:
    #         entity.resource = resources_idx.get(entity.instance.resource_uuid)
    #
    #     return entities
    #
    # def post_get(self):
    #     """Post get function. This function is used in get_entity method. Extend this function to extend description
    #     info returned after query.
    #
    #     :raise ApiManagerError:
    #     """
    #     pass
    #
    # def state_mapping(self, state):
    #     mapping = {
    #         SrvStatusType.PENDING: 'pending',
    #         SrvStatusType.BUILDING: 'building',
    #         SrvStatusType.CREATED: 'building',
    #         SrvStatusType.ACTIVE: 'available',
    #         SrvStatusType.DELETED: 'deregistered',
    #         SrvStatusType.DRAFT: 'transient',
    #         SrvStatusType.ERROR: 'error'
    #     }
    #     return mapping.get(state, 'error')
    #
    # def aws_info(self):
    #     """Get info as required by aws api
    #
    #     :param inst_service:
    #     :param resource:
    #     :param account_idx:
    #     :param instance_type_idx:
    #     :return:
    #     """
    #     instance_item = {}
    #
    #     # get config
    #     config = self.get_config('gateway')
    #     if config is None:
    #         config = {}
    #
    #     if self.resource is None:
    #         self.resource = {}
    #
    #     # get vpcs internal
    #     vpc_resources = dict_get(self.resource, 'vpc.internals')
    #     self.logger.warn(self.resource)
    #     self.logger.warn(vpc_resources)
    #     vpcs = []
    #     for vpc_resource in vpc_resources:
    #         self.logger.warn(vpc_resources)
    #         vpc_services, tot = self.controller.get_paginated_service_instances(resource_uuid=vpc_resource['uuid'],
    #                                                                             plugintype=ApiNetworkVpc.plugintype,
    #                                                                             details=False, with_permtag=False)
    #         if tot > 0:
    #             vpcs.append(vpc_services[0])
    #
    #     def vpc_state_mapping(state):
    #         mapping = {
    #             SrvStatusType.PENDING: 'pending',
    #             SrvStatusType.ACTIVE: 'available',
    #             SrvStatusType.DELETED: 'deregistered',
    #             SrvStatusType.DRAFT: 'transient',
    #             SrvStatusType.ERROR: 'error'
    #         }
    #         return mapping.get(state, 'error')
    #
    #     instance_item['ownerId'] = self.account.uuid
    #     instance_item['internetGatewayId'] = self.instance.uuid
    #     instance_item['nvl-state'] = self.state_mapping(self.instance.status)
    #     instance_item['attachmentSet'] = [
    #         {
    #             'VpcSecurityGroupMembership': {
    #                 'vpcId': vpc.uuid,
    #                 'state': vpc_state_mapping(vpc.status),
    #                 'nvl-vpcName': vpc.name
    #             }
    #         } for vpc in vpcs]
    #
    #     instance_item['tagSet'] = []
    #
    #     # custom params
    #     instance_item['nvl-name'] = self.instance.name
    #     instance_item['nvl-ownerAlias'] = self.account.name
    #
    #     return instance_item
    #
    # def pre_create(self, **params):
    #     """Check input params before resource creation. Use this to format parameters for service creation
    #     Extend this function to manipulate and validate create input params.
    #
    #     :param params: input params
    #     :return: resource input params
    #     :raise ApiManagerError:
    #     """
    #     # account_id = self.instance.account_id
    #
    #     # base quotas
    #     quotas = {
    #         'network.gateways': 1,
    #     }
    #
    #     # get container
    #     container_id = self.get_config('container')
    #     compute_zone = self.get_config('computeZone')
    #     # gateway = self.get_config('gateway')
    #
    #     uplink_vpc = self.get_config('uplink_vpc')
    #     transport_vpc = self.get_config('transport_vpc')
    #     primary_zone = self.get_config('primary_zone')
    #     primary_subnet = self.get_config('primary_subnet')
    #     primary_ip_address = self.get_config('primary_ip')
    #     secondary_zone = self.get_config('secondary_zone')
    #     secondary_subnet = self.get_config('secondary_subnet')
    #     secondary_ip_address = self.get_config('secondary_ip')
    #     admin_pwd = random_password(length=16, strong=True)
    #     dns = self.get_config('dns')
    #     dns_search = self.get_config('dns_search')
    #     flavor = self.get_config('flavor')
    #     volume_flavor = self.get_config('volume_flavor')
    #
    #     # check quotas
    #     self.check_quotas(compute_zone, quotas)
    #
    #     name = self.instance.name
    #
    #     data = {
    #         'name': name,
    #         'desc': name,
    #         'orchestrator_tag': 'default',
    #         'container': container_id,
    #         'compute_zone': compute_zone,
    #         'uplink_vpc': uplink_vpc,
    #         'transport_vpc': transport_vpc,
    #         'primary_zone': primary_zone,
    #         'primary_subnet': primary_subnet,
    #         'primary_ip_address': primary_ip_address,
    #         'secondary_zone': secondary_zone,
    #         'secondary_subnet': secondary_subnet,
    #         'secondary_ip_address': secondary_ip_address,
    #         'admin_pwd': admin_pwd,
    #         'dns': dns,
    #         'dns_search': dns_search,
    #         'flavor': flavor,
    #         'volume_flavor': volume_flavor,
    #         'type': 'vsphere',
    #         'host_group': 'default'
    #     }
    #     params['resource_params'] = data
    #     self.logger.debug('Pre create params: %s' % obscure_data(deepcopy(params)))
    #     return params
    #
    # #
    # # action
    # #
    # def attach_vpc(self, vpc):
    #     """Attach vpc to gateway
    #
    #     :param vpc: vpc id
    #     :return: True or False
    #     """
    #     # checks authorization
    #     self.controller.check_authorization(ApiServiceInstance.objtype, ApiServiceInstance.objdef,
    #                                         self.instance.objid, 'update')
    #
    #     # check vpc not already attached
    #     vpc_service = self.controller.get_service_instance(vpc)
    #     if self.has_vpc(vpc_service.resource_uuid) is True:
    #         raise ApiManagerError('vpc %s already attached to gateway %s' % (vpc, self.instance.uuid))
    #
    #     # task creation
    #     params = {
    #         'resource_params': {
    #             'action': 'attach-vpc',
    #             'vpc': vpc_service.resource_uuid
    #         }
    #     }
    #     self.action(**params)
    #     return True
    #
    # def detach_vpc(self, vpc):
    #     """Detach vpc from gateway
    #
    #     :param vpc: vpc id
    #     :return: True or False
    #     """
    #     # checks authorization
    #     self.controller.check_authorization(ApiServiceInstance.objtype, ApiServiceInstance.objdef,
    #                                         self.instance.objid, 'update')
    #
    #     # check vpc not already attached
    #     vpc_service = self.controller.get_service_instance(vpc)
    #     if self.has_vpc(vpc_service.resource_uuid) is False:
    #         raise ApiManagerError('vpc %s is not attached to gateway %s' % (vpc, self.instance.uuid))
    #
    #     # task creation
    #     params = {
    #         'resource_params': {
    #             'action': 'detach-vpc',
    #             'vpc': vpc_service.resource_uuid
    #         }
    #     }
    #     self.action(**params)
    #     return True
    #
    # #
    # # resource client method
    # #
    # @trace(op='view')
    # def has_vpc(self, vpc_resource_uuid):
    #     """Check vpc already attached
    #
    #     :return: True if vpc is attached
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     resource = self.get_resource()
    #     vpc_resources = dict_get(resource, 'vpc.internals', default=[])
    #     for vpc_resource in vpc_resources:
    #         if vpc_resource_uuid == vpc_resource['uuid']:
    #             return True
    #     return False
    #
    # @trace(op='view')
    # def get_resource(self):
    #     """Get resource info
    #
    #     :rtype: dict
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     uri = '/v1.0/nrs/provider/gateways/%s' % self.instance.resource_uuid
    #     instance = self.controller.api_client.admin_request('resource', uri, 'get', data='').get('gateway')
    #     self.logger.debug('Get gateway resource: %s' % truncate(instance))
    #     return instance
    #
    # @trace(op='view')
    # def list_resources(self, zones=None, uuids=None, tags=None, page=0, size=100):
    #     """Get resource info
    #
    #     :return: Dictionary with resources info.
    #     :rtype: dict
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     if zones is None:
    #         zones = []
    #     if uuids is None:
    #         uuids = []
    #     if tags is None:
    #         tags = []
    #     data = {
    #         'size': size,
    #         'page': page
    #     }
    #     if len(zones) > 0:
    #         data['parent_list'] = ','.join(zones)
    #     if len(uuids) > 0:
    #         data['uuids'] = ','.join(uuids)
    #     if len(tags) > 0:
    #         data['tags'] = ','.join(tags)
    #
    #     instances = self.controller.api_client.admin_request('resource', '/v1.0/nrs/provider/gateways', 'get',
    #                                                          data=urlencode(data)).get('gateways', [])
    #     self.controller.logger.debug('Get gateway resources: %s' % truncate(instances))
    #     return instances
    #
    # @trace(op='insert')
    # def create_resource(self, task, *args, **kvargs):
    #     """Create resource
    #
    #     :param args: custom positional args
    #     :param kvargs: custom key=value args
    #     :return: True
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     data = {'gateway': args[0]}
    #     try:
    #         uri = '/v1.0/nrs/provider/gateways'
    #         res = self.controller.api_client.admin_request('resource', uri, 'post', data=data)
    #         uuid = res.get('uuid', None)
    #         taskid = res.get('taskid', None)
    #         self.logger.debug('Create gateway resource: %s' % uuid)
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
    #     if uuid is not None and taskid is not None:
    #         self.set_resource(uuid)
    #         self.update_status(SrvStatusType.PENDING)
    #         self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
    #         self.update_status(SrvStatusType.CREATED)
    #         self.controller.logger.debug('Update gateway resource: %s' % uuid)
    #
    #     # set default routes
    #     data = {'role': 'default'}
    #     try:
    #         uri = '/v1.0/nrs/provider/gateways/%s/route/default' % uuid
    #         res = self.controller.api_client.admin_request('resource', uri, 'put', data=data)
    #         taskid = res.get('taskid', None)
    #         self.logger.debug('set gateway %s default routes - start' % uuid)
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
    #         self.controller.logger.debug('set gateway %s default routes' % uuid)
    #
    #     return uuid
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
    #     # create new rules
    #     action = kvargs.get('action', None)
    #
    #     if action == 'attach-vpc':
    #         vpc = kvargs.get('vpc')
    #         self.__attach_vpc_resource(task, vpc)
    #     elif action == 'detach-vpc':
    #         vpc = kvargs.get('vpc')
    #         self.__detach_vpc_resource(task, vpc)
    #
    #     return True
    #
    # def __attach_vpc_resource(self, task, vpc):
    #     """attach vp to gateway. Api call
    #
    #     :param task: celery task
    #     :param vpc: vpc resource uuid
    #     :return:
    #     """
    #     uuid = self.instance.resource_uuid
    #     try:
    #         data = {'vpc': vpc}
    #         uri = '/v1.0/nrs/provider/gateways/%s/vpc' % uuid
    #         res = self.controller.api_client.admin_request('resource', uri, 'post', data=data)
    #         taskid = res.get('taskid', None)
    #         self.logger.debug('attach vpc %s to gateway %s - start' % (vpc, uuid))
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
    #         self.controller.logger.debug('attach vpc %s to gateway %s' % (vpc, uuid))
    #
    # def __detach_vpc_resource(self, task, vpc):
    #     """detach vp from gateway. Api call
    #
    #     :param task: celery task
    #     :param vpc: vpc resource uuid
    #     :return:
    #     """
    #     uuid = self.instance.resource_uuid
    #     try:
    #         data = {'vpc': vpc}
    #         uri = '/v1.0/nrs/provider/gateways/%s/vpc' % uuid
    #         res = self.controller.api_client.admin_request('resource', uri, 'delete', data=data)
    #         taskid = res.get('taskid', None)
    #         self.logger.debug('detach vpc %s from gateway %s - start' % (vpc, uuid))
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
    #         self.controller.logger.debug('detach vpc %s from gateway %s' % (vpc, uuid))


class ApiNetworkSiteToSiteVpn(AsyncApiServiceTypePlugin):
    plugintype = "NetworkSiteToSiteVpn"
    objname = "sitetositevpn"

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


class ApiNetworkVpc(AsyncApiServiceTypePlugin):
    plugintype = "NetworkVpc"
    objname = "vpc"

    class state_enum(object):
        """enumerate state name esposed by api"""

        unknown = "unknown"
        pending = "pending"
        available = "available"
        deregistered = "deregistered"
        transient = "transient"
        error = "error"

    def __init__(self, *args, **kvargs):
        """ """
        ApiServiceTypePlugin.__init__(self, *args, **kvargs)

        self.child_classes = []

    def get_tenancy(self):
        """Get vpc tenancy"""
        tenancy = self.get_config("vpc").get("InstanceTenancy", None)
        if tenancy is None:
            tenancy = "default"
        return tenancy

    def get_cidr(self):
        """Get vpc cidr"""
        cidr = self.get_config("vpc").get("CidrBlock", None)
        return cidr

    def info(self):
        """Get object info
        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = ApiServiceTypePlugin.info(self)
        info.update({})
        return info

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: self.state_enum.pending,  # 'pending',
            SrvStatusType.ACTIVE: self.state_enum.available,  # 'available',
            SrvStatusType.DELETED: self.state_enum.deregistered,  # 'deregistered',
            SrvStatusType.DRAFT: self.state_enum.transient,  # 'transient',
            SrvStatusType.ERROR: self.state_enum.error,  # 'error'
        }
        return mapping.get(state, self.state_enum.unknown)

    @staticmethod
    def customize_list(controller: ServiceController, entities: List, *args, **kvargs) -> List:
        # da capire
        # def customize_list(controller: ServiceController, entities: List[ApiNetworkVpc], *args, **kvargs) \
        #         -> List[ApiNetworkVpc]:
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

        # get resources
        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.account = account_idx.get(account_id)

        return entities

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.account = self.controller.get_account(str(self.instance.account_id))

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.resource is None:
            self.resource = {}

        # get child subnets
        subnets = self.instance.get_child_instances(plugintype=ApiNetworkSubnet.plugintype)

        instance_item = {}
        instance_item["vpcId"] = self.instance.uuid
        instance_item["state"] = self.state_mapping(self.instance.status)
        instance_item["cidrBlock"] = self.get_cidr()

        instance_item["cidrBlockAssociationSet"] = []
        instance_item["ipv6CidrBlockAssociationSet"] = []
        for subnet in subnets:
            cidr_block_association_set = {}
            cidr_block_association_set["associationId"] = subnet.uuid
            cidr_block_association_set["cidrBlock"] = subnet.get_main_config().get_json_property("cidr")
            cidr_block_association_set["cidrBlockState"] = {
                "state": "associated",
                "statusMessage": "",
            }
            instance_item["cidrBlockAssociationSet"].append(cidr_block_association_set)

        instance_item["dhcpOptionsId"] = ""
        instance_item["instanceTenancy"] = self.get_tenancy()
        instance_item["isDefault"] = False
        instance_item["tagSet"] = []

        instance_item["ownerId"] = self.account.uuid
        # custom params
        instance_item["nvl-name"] = self.instance.name
        instance_item["nvl-vpcOwnerAlias"] = self.account.name
        instance_item["nvl-vpcOwnerId"] = self.account.uuid
        instance_item["nvl-resourceId"] = self.instance.resource_uuid

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
            "compute.networks": 1,
        }

        # get container
        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")
        vpc_config = self.get_config("vpc")
        tenancy = vpc_config.get("InstanceTenancy", "default")
        cidr = vpc_config.get("CidrBlock", None)

        # check quotas
        self.check_quotas(compute_zone, quotas)

        # select cidr
        if cidr is None:
            cidr = self.get_config("cidr")

        # select vpc type
        if tenancy == "default":
            vpc_type = "shared"
            networks = self.get_config("networks")
        elif tenancy == "dedicated":
            vpc_type = "private"
            networks = None

        name = "%s-%s" % (self.instance.name, id_gen(length=8))

        data = {
            "container": container_id,
            "name": name,
            "desc": self.instance.desc,
            "compute_zone": compute_zone,
            "networks": networks,
            "type": vpc_type,
            "cidr": cidr,
        }

        params["resource_params"] = data
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    #
    # resource client method
    #
    @trace(op="view")
    def list_resources(self, zones=[], uuids=[], tags=[], page=0, size=-1):
        """Get resources info

        :return: Dictionary with resources info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {"size": size, "page": page}
        if len(zones) > 0:
            data["parent_list"] = ",".join(zones)
        if len(uuids) > 0:
            data["uuids"] = ",".join(uuids)
        if len(tags) > 0:
            data["tags"] = ",".join(tags)
        self.logger.debug("list_vpc_resources %s" % data)

        instances = self.controller.api_client.admin_request(
            "resource", "/v2.0/nrs/provider/vpcs", "get", data=urlencode(data)
        ).get("instances", [])
        self.logger.debug("Get compute vpc resources: %s" % truncate(instances))
        return instances

    @trace(op="insert")
    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        vpc_type = args[0]["type"]
        networks = args[0].pop("networks", None)

        data = {"vpc": args[0]}
        try:
            uri = "/v2.0/nrs/provider/vpcs"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create resource: %s" % uuid)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.message)
            raise ApiManagerError(ex.message)

        # set resource uuid
        if uuid is not None and taskid is not None:
            self.set_resource(uuid)
            self.update_status(SrvStatusType.PENDING)
            self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
            self.update_status(SrvStatusType.CREATED)
            self.logger.debug("Update compute vpc resources: %s" % uuid)

        # add shared network to vpc
        if vpc_type == "shared":
            try:
                data = {"site": [{"network": n} for n in networks]}
                uri = "/v2.0/nrs/provider/vpcs/%s/network" % uuid
                res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
                uuid = res.get("uuid", None)
                taskid = res.get("taskid", None)
                self.logger.debug("Append site networks to vpc %s - start" % uuid)
            except ApiManagerError as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.value)
                raise
            except Exception as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.message)
                raise ApiManagerError(ex.message)

            # set resource uuid
            if uuid is not None and taskid is not None:
                self.set_resource(uuid)
                self.update_status(SrvStatusType.PENDING)
                self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
                self.update_status(SrvStatusType.CREATED)
                self.logger.debug("Append site networks to vpc %s - end" % uuid)

        return uuid

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # get site networks to deassign
        networks = self.get_config("networks")

        # remove shared network from vpc
        if self.get_tenancy() == "default":
            try:
                data = {"site": [{"network": n} for n in networks]}
                uri = "/v2.0/nrs/provider/vpcs/%s/network" % self.instance.resource_uuid
                res = self.controller.api_client.admin_request("resource", uri, "delete", data=data)
                uuid = res.get("uuid", None)
                taskid = res.get("taskid", None)
                self.logger.debug("Remove site networks from vpc %s - start" % self.instance.resource_uuid)
            except ApiManagerError as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.value)
                raise
            except Exception as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.message)
                raise ApiManagerError(ex.message)

            # set resource uuid
            if uuid is not None and taskid is not None:
                self.set_resource(uuid)
                self.update_status(SrvStatusType.PENDING)
                self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
                self.update_status(SrvStatusType.CREATED)
                self.logger.debug("Remove site networks from vpc %s - end" % self.instance.resource_uuid)

        return ApiServiceTypePlugin.delete_resource(self, *args, **kvargs)


class ApiNetworkSecurityGroup(AsyncApiServiceTypePlugin):
    plugintype = "NetworkSecurityGroup"
    objname = "securitygroup"

    class state_enum(object):
        """enumerate state name exposed by api"""

        pending = "pending"
        available = "available"
        deregistering = "deregistering"
        deregistered = "deregistered"
        transient = "transient"
        transient = "transient"
        error = "error"
        updating = "updating"
        unknown = "unknown"

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
        info = ApiServiceTypePlugin.info(self)
        info.update({})
        return info

    @staticmethod
    def customize_list(controller: ServiceController, entities, *args, **kvargs):
        # da capire
        # def customize_list(controller: ServiceController, entities: List[ApiNetworkSecurityGroup], *args, **kvargs):
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
        vpc_idx = controller.get_service_instance_idx(ApiNetworkVpc.plugintype)
        security_group_idx = controller.get_service_instance_idx(ApiNetworkSecurityGroup.plugintype)

        # get resources
        # zones = []
        resources = []
        # account_id_list = []
        vpc_list = []
        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.account = account_idx.get(account_id)
            entity.account_idx = account_idx
            entity.vpc_idx = vpc_idx
            entity.security_group_idx = security_group_idx
            if entity.instance.resource_uuid is not None:
                resources.append(entity.instance.resource_uuid)

            config = entity.get_config("security_group")
            if config is not None:
                controller.logger.warn(config.get("VpcId"))
                vpc = vpc_idx.get(config.get("VpcId"))
                vpc_list.append(vpc.resource_uuid)

        if len(resources) > 3:
            resources = []
        resources_list = ApiNetworkSecurityGroup(controller).list_resources(vpcs=vpc_list, uuids=resources)
        resources_idx = {r["uuid"]: r for r in resources_list}

        # assign resources
        for entity in entities:
            resource = resources_idx.get(entity.instance.resource_uuid, None)
            entity.resource = resource
            if resource is not None:
                entity.rules = resource.pop("rules", [])
            else:
                entity.rules = []

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: self.state_enum.pending,  # 'pending',
            SrvStatusType.ACTIVE: self.state_enum.available,  # 'available',
            SrvStatusType.DELETING: self.state_enum.deregistering,  # 'deregistering',
            SrvStatusType.DELETED: self.state_enum.deregistered,  # 'deregistered',
            SrvStatusType.DRAFT: self.state_enum.transient,  # 'transient',
            SrvStatusType.CREATED: self.state_enum.transient,  # 'transient',
            SrvStatusType.ERROR: self.state_enum.error,  # 'error',
            SrvStatusType.UPDATING: self.state_enum.updating,  # 'updating'
        }
        return mapping.get(state, self.state_enum.unknown)

    def set_service_info(self, ip_protocol, ip_from_port_range, ip_to_port_range):
        """Get rule printed info

        :param ip_protocol: protocol
        :param ip_from_port_range: from port
        :param ip_to_port_range: to port
        :return:
        """
        if ip_protocol == "1":
            if ip_from_port_range == -1:
                service_info = {"subprotocol": "-1", "protocol": ip_protocol}
            else:
                service_info = {
                    "subprotocol": ("%s" % ip_from_port_range),
                    "protocol": ip_protocol,
                }
        elif ip_from_port_range == -1:
            service_info = {"port": "*", "protocol": ip_protocol}
        elif ip_from_port_range == ip_to_port_range:
            service_info = {
                "port": ("%s" % ip_from_port_range),
                "protocol": ip_protocol,
            }
        else:
            service_info = {
                "port": ("%s-%s" % (ip_from_port_range, ip_to_port_range)),
                "protocol": ip_protocol,
            }
        return service_info

    def get_ipv_range_list(self, data, range_type):
        """Get list of ip range

        :param data: input data to parse
        :param range_type: type of range. Can be IpRanges, Ipv6Ranges
        :return: list of ip range
        """
        ipv_range_list = []

        ip_ranges = data.get(range_type, [])
        for ip_range in ip_ranges:
            cidrip = ip_range.get("CidrIp", None)
            if cidrip is not None:
                try:
                    ipaddress.ip_network(cidrip)
                except ValueError as ex:
                    self.logger.error("Add Rule", exc_info=2)
                    raise ApiManagerError(f"Error parsing CidrIp {cidrip}: {ex.__str__()}", code=400)
                ipv_range_list.append(cidrip)

        return ipv_range_list

    def get_group_list(self, data):
        """Get list of security group

        :param data: input data to parse
        :return: list of securit group
        """
        group_list = []

        for user_sg_data in data.get("UserIdGroupPairs", []):
            # manage source of type SecurityGroup by id
            if user_sg_data.get("GroupName", None) is not None:
                sg_perm_plugin = self.controller.get_service_type_plugin(
                    user_sg_data.get("GroupName"),
                    plugin_class=ApiNetworkSecurityGroup,
                    details=False,
                )
                sg_perm_inst = sg_perm_plugin.instance
                group_list.append(sg_perm_inst.resource_uuid)
        return group_list

    def get_rule_from_filter(self, data, rule_type):
        """Get list of rules from a filter

        :param data: input data to parse
        :param rule_type: type of rule. Can bu RULE_GROUP_INGRESS, RULE_GROUP_EGRESS
        :return: list of rule
        """
        ip_permission_list = data.get("IpPermissions_N", [])
        if not ip_permission_list:
            raise ApiManagerError("The parameter IpPermissions.N is empty, provide at least  an item", 400)

        # only one filter is supported for the moment
        ip_permission = ip_permission_list[0]

        # check ports and protocol
        ip_from_port_range = ip_permission.get("FromPort")
        ip_to_port_range = ip_permission.get("ToPort")

        if ip_permission.get("IpProtocol") == "-1":
            service = "*:*"
        else:
            proto = self.convert_rule_to_resource_proto(ip_permission.get("IpProtocol"))
            if proto == "1" and ip_from_port_range == -1 or ip_to_port_range == -1:
                port = "-1"
            elif ip_from_port_range == -1 or ip_to_port_range == -1:
                port = "*"
            elif ip_from_port_range >= ip_to_port_range:
                port = ip_to_port_range
            else:
                port = "%s-%s" % (ip_from_port_range, ip_to_port_range)
            service = "%s:%s" % (proto, port)

        # check source/destionation
        if len(ip_permission.get("UserIdGroupPairs", [])) > 0 and (
            len(ip_permission.get("IpRanges", [])) > 0 or len(ip_permission.get("Ipv6Ranges", [])) > 0
        ):
            raise ApiManagerError(
                "Only one of IpPermissions.N.UserIdGroupPairs, IpPermissions.N.IpRanges, "
                "IpPermissions.N.Ipv6Ranges should be supplied",
                400,
            )
        if (
            len(ip_permission.get("UserIdGroupPairs", [])) == 0
            and len(ip_permission.get("IpRanges", [])) == 0
            and len(ip_permission.get("Ipv6Ranges", [])) == 0
        ):
            raise ApiManagerError(
                "One of IpPermissions.N.UserIdGroupPairs, IpPermissions.N.IpRanges, "
                "IpPermissions.N.Ipv6Ranges should be supplied",
                400,
            )

        # get cidr ipv4
        ipv4_range_list = self.get_ipv_range_list(ip_permission, "IpRanges")
        if len(ipv4_range_list) > 0:
            others = ["Cidr:%s" % i for i in ipv4_range_list]

        # get cidr ipv6
        ipv6_range_list = self.get_ipv_range_list(ip_permission, "Ipv6Ranges")
        if len(ipv6_range_list) > 0:
            others = ["Cidr:%s" % i for i in ipv6_range_list]

        # get security group
        group_list = self.get_group_list(ip_permission)
        if len(group_list) > 0:
            others = ["SecurityGroup:%s" % i for i in group_list]

        rules = self.list_rule_resources(others, service, rule_type)
        self.logger.debug("Get rules from filter: %s" % truncate(rules))
        return rules

    def get_rule_ip_permission(self, data, sg_inst, rule_type):
        """Get rule ip permission

        :param data: input data to parse
        :param sg_inst: security group instance
        :param rule_type: type of rule. Can bu RULE_GROUP_INGRESS, RULE_GROUP_EGRESS
        :return: list of ip permissions
        """
        sg_perm_inst = None
        sg_perm_inst_value = None
        sg_perm_type = "SecurityGroup"
        # sg_perm_user = None
        # vpc_perm_inst = None

        ip_permission_list = data.get("rule").get("IpPermissions_N", [])
        if not ip_permission_list:
            raise ApiManagerError("The parameter IpPermissions.N is empty, provide at least  an item", 400)

        # TODO management IpPermissions_N array object
        for ip_permission in ip_permission_list:
            if not ip_permission.get("UserIdGroupPairs", []) and len(ip_permission.get("IpRanges", [])) == 0:
                sg_perm_inst = sg_inst
                sg_perm_inst_value = sg_perm_inst.resource_uuid

            if len(ip_permission.get("UserIdGroupPairs", [])) > 0 and (
                len(ip_permission.get("IpRanges", [])) > 0 or len(ip_permission.get("Ipv6Ranges", [])) > 0
            ):
                raise ApiManagerError(
                    "can be supplied parameter IpPermissions.N.UserIdGroupPairs or alternatively "
                    "IpPermissions.N.IpRanges | IpPermissions.N.Ipv6Ranges",
                    400,
                )

            # convert protocol
            ip_protocol = self.convert_rule_to_resource_proto(ip_permission.get("IpProtocol"))
            ip_from_port_range = ip_permission.get("FromPort")
            ip_to_port_range = ip_permission.get("ToPort")

            if ip_from_port_range == -1:
                ip_to_port_range = -1
                self.logger.debug(
                    "parameters IpPermissions.N.ToPort has been set to IpPermissions.N.FromPort with " "-1 value"
                )
            elif ip_from_port_range > ip_to_port_range:
                raise ApiManagerError(
                    "Parameter IpPermissions.N.FromPort and IpPermissions.N.ToPort have a wrong " "value",
                    400,
                )

            if ip_permission.get("IpProtocol") == "-1" and (ip_from_port_range != -1 or ip_to_port_range != -1):
                raise ApiManagerError(
                    "Parameter IpPermissions.N.Protocol -1 accepts only default port value -1 ",
                    400,
                )

            # set service
            service = self.set_service_info(ip_protocol, ip_from_port_range, ip_to_port_range)

            # manage source of type SecurityGroup
            if ip_permission.get("UserIdGroupPairs", []):
                user_sg_data_list = ip_permission.get("UserIdGroupPairs", [])
                # TODO Management of UserIdGroupPairs array
                for user_sg_data in user_sg_data_list:
                    # manage source of type SecurityGroup by id
                    if user_sg_data.get("GroupName", None) is not None:
                        sg_perm_plugin = self.controller.get_service_type_plugin(
                            user_sg_data.get("GroupName"),
                            plugin_class=ApiNetworkSecurityGroup,
                            details=False,
                        )
                        sg_perm_inst = sg_perm_plugin.instance
                        sg_perm_inst_value = sg_perm_inst.resource_uuid

            ipv_range_list = ApiNetworkSecurityGroup(self.controller).get_ipv_range_list(ip_permission, "IpRanges")
            # ipv_range_list.extend(ApiNetworkSecurityGroup(controller).get_ipv_range_list(ip_permission, 'Ipv6Ranges'))
            # TODO Management array value ipv4 or ipv6
            for ipv_range in ipv_range_list:
                sg_perm_inst_value = ipv_range
                sg_perm_type = "Cidr"
                break

        # create rule
        rule = {}
        if rule_type == __RULE_GROUP_EGRESS__:
            rule["source"] = {"type": "SecurityGroup", "value": sg_inst.resource_uuid}
            rule["destination"] = {"type": sg_perm_type, "value": sg_perm_inst_value}
        else:
            rule["source"] = {"type": sg_perm_type, "value": sg_perm_inst_value}
            rule["destination"] = {
                "type": "SecurityGroup",
                "value": sg_inst.resource_uuid,
            }
        rule["service"] = service

        return rule

    def convert_rule_proto(self, proto):
        mapping = {
            "-1": "-1",
            "6": "tcp",
            "17": "udp",
            "1": "icmp",
        }
        return mapping.get(str(proto), None)

    def convert_rule_to_resource_proto(self, proto):
        mapping = {
            "tcp": "6",
            "udp": "17",
            "icmp": "1",
            "-1": "*",
        }
        return mapping.get(proto, "*")

    def get_rule_info_params(self, item, item_list):
        """Get rule info params

        :param item:
        :param item_list:
        :return:
        """
        res = {}
        item_type = item.get("type")
        item_value = item.get("value")
        if item_type == "SecurityGroup":
            sg_service = self.security_group_idx.get(item_value)

            if sg_service is not None:
                res["groupId"] = sg_service.uuid
                res["userId"] = self.account_idx.get(str(sg_service.account_id)).uuid
                # custom param
                res["groupName"] = sg_service.name
                res["nvl-userName"] = self.account_idx.get(str(sg_service.account_id)).name
            else:
                res["groupId"] = ""
                res["userId"] = ""
                # custom param
                res["groupName"] = ""
                res["nvl-userName"] = ""

            item_list["groups"].append(res)
        elif item_type == "Cidr":
            res["cidrIp"] = item_value
            item_list["ipRanges"].append(res)
        return item_list

    def get_rule_info(self, resource, direction, reserved, state):
        """Get rule info

        :param sg_res_idx: security groups indexed by resource id
        :param direction: can be ingress or egress
        :param account_idx: index of account reference
        :param reserved: rule reservation
        :param state: rule state
        :param resource: dict like

            "source": {
                "type": "Cidr",
                "value": "###.###.###.###/##"
            },
            "destination": {
                "type": "SecurityGroup",
                "value": "<uuid>"
            },
            "service": {
                "protocol": "*",
                "port": "*"
            }

        :return: rule info
        """
        instance_item = {}

        service = resource.get("service", {})
        protocol = service.get("protocol", "-1")
        if protocol == "*":
            protocol = "-1"
        elif protocol == "1":
            subprotocol = service.get("subprotocol", None)
            if subprotocol is not None:
                instance_item["fromPort"] = int(subprotocol)
                instance_item["toPort"] = int(subprotocol)
        port = service.get("port", None)
        if port is not None and port != "*":
            if port.find("-") > 0:
                s_from_port, s_to_port = port.split("-")
                instance_item["fromPort"] = int(s_from_port)
                instance_item["toPort"] = int(s_to_port)
            else:
                instance_item["fromPort"] = instance_item["toPort"] = int(port)

        instance_item["ipProtocol"] = self.convert_rule_proto(protocol)
        instance_item["groups"] = []
        instance_item["ipRanges"] = []
        source = resource.get("source", {})
        dest = resource.get("destination", {})
        if direction == "ingress":
            instance_item = self.get_rule_info_params(source, instance_item)
        elif direction == "egress":
            instance_item = self.get_rule_info_params(dest, instance_item)

        # custom fields
        instance_item["nvl-reserved"] = reserved
        instance_item["nvl-state"] = state

        return instance_item

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        instance_item = {}

        res_uuid = None
        if isinstance(self.resource, dict):
            res_uuid = self.resource.get("uuid")
        instance_item["vpcId"] = ""
        instance_item["nvl-vpcName"] = ""
        instance_item["nvl-sgOwnerAlias"] = ""
        instance_item["nvl-sgOwnerId"] = ""
        config = self.get_config("security_group")

        if config is not None:
            vpc = self.vpc_idx.get(config.get("VpcId"))
            if vpc is not None:
                instance_item["vpcId"] = getattr(vpc, "uuid", None)
                instance_item["nvl-vpcName"] = getattr(vpc, "name", None)
                instance_item["nvl-sgOwnerAlias"] = self.account.name
                instance_item["nvl-sgOwnerId"] = self.account.uuid

        instance_item["ownerId"] = str(self.instance.account_id)
        instance_item["groupDescription"] = self.instance.desc
        instance_item["groupName"] = self.instance.name
        instance_item["groupId"] = self.instance.uuid
        instance_item["tagSet"] = []
        instance_item["ipPermissions"] = []
        instance_item["ipPermissionsEgress"] = []
        for rule in self.rules:
            state = rule.get("state", None)
            rule = rule.get("attributes", {})
            reserved = rule.get("reserved")
            rule = rule.get("configs", {})
            source = rule.get("source", {})
            dest = rule.get("destination", {})

            if dest.get("type") == "SecurityGroup" and dest.get("value") == res_uuid:
                instance_item["ipPermissions"].append(self.get_rule_info(rule, "ingress", reserved, state))
            if source.get("type") == "SecurityGroup" and source.get("value") == res_uuid:
                instance_item["ipPermissionsEgress"].append(self.get_rule_info(rule, "egress", reserved, state))

        # custom params
        instance_item["nvl-state"] = self.state_mapping(self.instance.status)
        instance_item["nvl-stateReason"] = {"nvl-code": None, "nvl-message": None}
        if instance_item["nvl-state"] == "error":
            instance_item["nvl-stateReason"] = {
                "nvl-code": 400,
                "nvl-message": self.instance.last_error,
            }

        return instance_item

    def check_rule_reservation(self, rule):
        """Check if rule is reserved. A reserved rule is created from template and can not be removed

        :param rule: rule data
        :return: True if reserved
        """
        rule = rule.get("attributes", {})
        reserved = rule.get("reserved")
        return reserved

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        # account_id = self.instance.account_id

        # base quotas
        quotas = {
            "compute.security_groups": 1,
            "compute.security_group_rules": 0,
        }

        # get container
        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")
        vpc = self.get_parent()

        # check quotas
        self.check_quotas(compute_zone, quotas)

        name = "%s-%s" % (self.instance.name, id_gen(length=8))

        data = {
            "container": container_id,
            "name": name,
            "desc": self.instance.desc,
            "vpc": vpc.resource_uuid,
            "compute_zone": compute_zone,
        }
        params["resource_params"] = data
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    def pre_patch(self, **params):
        """Pre patch function. This function is used in update method. Extend this function to manipulate and
        validate patch input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        # get service definition
        service_definition = self.controller.get_service_def(self.instance.service_definition_id)
        def_config = service_definition.get_main_config()
        rules = def_config.get_json_property("rules")

        # set rules from definition
        self.set_config("rules", rules)

        return params

    def aws_create_rule(self, security_group, rule, rule_type):
        """Create new rule using aws api

        :param security_group: source or destination security group service instance
        :param rule: rule data
        :param rule_type: rule type: ingress or egress
        :return:
        """
        # res = False

        # checks authorization
        # todo: authorization must be reconsidered when use process
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            security_group.objid,
            "update",
        )

        # check rule already exists
        rules = self.get_rule_from_filter(rule, rule_type)
        if len(rules) > 0:
            raise ApiManagerError("Rule with the same parameters already exists")

        rule_data = self.get_rule_ip_permission({"rule": rule}, self.instance, rule_type)

        _res = self.rule_factory(rule_data, reserved=False)
        return True

    def aws_delete_rule(self, security_group, rule, rule_type):
        """Delete a rule using aws api

        :param security_group: source or destination security group service instance
        :param rule: rule data
        :param rule_type: rule type: ingress or egress
        :return:
        """
        # res = False

        # checks authorization
        # todo: authorization must be reconsidered when use process
        self.controller.check_authorization(
            ApiServiceInstance.objtype,
            ApiServiceInstance.objdef,
            security_group.objid,
            "update",
        )
        self.logger.warn(rule)
        # check rule already exists
        rules = self.get_rule_from_filter(rule, rule_type)
        for rule in rules:
            if self.check_rule_reservation(rule) is True:
                raise ApiManagerError("Rule is reserved and can not be deleted")

            # delete rule
            self.rule_delete_factory(rule)

        return True

    def rule_factory(self, rule, reserved=False):
        """Factory used toe create a rule using a task or a camunda process.

        :param dict rule: rule definition
        :param boolean reserved: flag for reserved rules (not deletable)
        :rtype: bool
        """
        try:
            self.logger.info("Add Rule for instance %s" % self.instance.uuid)
            process_key, template = self.get_bpmn_process_key(self.instance, ApiServiceTypePlugin.PROCESS_ADD_RULE)
            if process_key is not None and ApiServiceTypePlugin.INVALID_PROCESS_KEY != process_key:
                # asynchronous way
                data = self.prepare_add_rule_process_variables(self.instance, template, reserved=reserved, rule=rule)
                res = self.camunda_engine.process_instance_start_processkey(process_key, variables=data)
                self.logger.debug("Call bpmn process %s: %s" % (process_key, res))
                process_id = res.get("id")
                upd_data = {"bpmn_process_id": process_id}
                self.instance.update(**upd_data)
            else:
                # task creation
                params = {"resource_params": {"action": "add-rules", "rules": [rule]}}
                self.action(**params)

        except Exception:
            self.logger.error("Add Rule", exc_info=2)
            raise ApiManagerError("Error Adding rule for instance %s" % self.instance.uuid)

    def rule_delete_factory(self, rule):
        """Factory used toe delete a rule using a task or a camunda process.

        :param dict rule: rule definition
        :param boolean reserved: flag for reserved rules (not deletable)
        :rtype: bool
        """
        try:
            self.logger.info("Delete Rule for instance %s" % self.instance.uuid)
            process_key, _template = self.get_bpmn_process_key(self.instance, ApiServiceTypePlugin.PROCESS_ADD_RULE)
            if process_key is not None and ApiServiceTypePlugin.INVALID_PROCESS_KEY != process_key:
                # asynchronous way TODO
                pass
            else:
                # task creation
                params = {"resource_params": {"action": "del-rules", "rules": [rule]}}
                self.action(**params)

        except Exception:
            self.logger.error("Add Rule", exc_info=2)
            raise ApiManagerError("Error removing rule for instance %s" % self.instance.uuid)

    #
    # resource client method
    #
    def list_resources(self, vpcs=[], uuids=[], page=0, size=-1):
        """List sg resource

        :return: Dictionary with resources info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # todo: improve rules filter
        data = {"size": size, "page": page}
        if len(vpcs) > 0:
            data["parent_list"] = ",".join([x for x in vpcs if x is not None])
        if len(uuids) > 0:
            data["uuids"] = ",".join(uuids)

        sgs = self.controller.api_client.admin_request(
            "resource",
            "/v1.0/nrs/provider/security_groups",
            "get",
            data=urlencode(data),
        ).get("security_groups", [])
        self.controller.logger.debug("Get compute sg resources: %s" % truncate(sgs))

        return sgs

    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        compute_zone = args[0].pop("compute_zone")
        container = args[0].get("container")
        data = {"security_group": args[0]}
        try:
            uri = "/v1.0/nrs/provider/security_groups"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create security group %s resource with job %s" % (uuid, taskid))
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.message)
            raise ApiManagerError(ex.message)

        # set resource uuid
        if uuid is not None and taskid is not None:
            self.set_resource(uuid)
            self.update_status(SrvStatusType.PENDING)
            self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
            self.update_status(SrvStatusType.CREATED)
            self.controller.logger.debug("Update security group resource: %s" % uuid)

            # create rules
            rules = self.get_config("rules")
            for rule in rules:
                self.create_resource_rule(task, compute_zone, rule, container, reserved=True)
            self.logger.debug("Create security group %s resource with all rules" % uuid)

        return uuid

    def create_resource_rule(self, task, compute, rule, container, reserved=False):
        """Create rule

        :param task: celery task reference
        :param compute: computeservice resource uuid
        :param rule: rule definition
        :param container: container name
        :param reserved: flag for reserved rules (not deletable)
        :rtype: bool
        """
        # check rule contains reference to main security group
        if rule.get("source").get("value") == "<resource id of SecurityGroup>":
            rule["source"]["value"] = self.instance.resource_uuid
        if rule.get("destination").get("value") == "<resource id of SecurityGroup>":
            rule["destination"]["value"] = self.instance.resource_uuid

        name = "%s-rule-%s" % (self.instance.name, id_gen(length=8))
        rule_data = {
            "rule": {
                "container": container,
                "name": name,
                "desc": name,
                "compute_zone": compute,
                "source": rule.get("source"),
                "destination": rule.get("destination"),
                "service": rule.get("service"),
                "reserved": reserved,
            }
        }
        self.logger.debug("Rule data: %s" % rule_data)

        # TODO: check rule can be created
        # if reserved is False and rule.get('destination').get('type') == 'SecurityGroup':
        #     source = '%s:%s' % (rule.get('source').get('type'), rule.get('source').get('value'))
        #     dest = rule.get('destination').get('value')
        #     protocol = '%s:*' % rule.get('service').get('protocol')
        #     port = rule.get('service').get('port')
        #     self.check_rule_config_allowed(source, dest, protocol, port)

        # create rule
        res = self.controller.api_client.admin_request(
            "resource",
            "/v1.0/nrs/provider/rules",
            "post",
            data=rule_data,
            other_headers=None,
        )

        # wait job
        taskid = res.get("taskid", None)
        if taskid is not None:
            self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
        else:
            raise ApiManagerError("Rule job does not started")

        self.logger.debug("Create rule resource %s in security group %s" % (rule, self.instance.uuid))
        return True

    def update_resource(self, task, *args, **kvargs):
        """Update resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        # compute_zone = self.get_config('computeZone')
        # container = self.get_config('container')
        #
        # # create new rules
        # action = kvargs.get('action', None)
        # rules = kvargs.get('rules', [])
        # for rule in rules:
        #     if action == 'add-rules':
        #         self.create_resource_rule(compute_zone, rule, container, reserved=False)
        #     elif action == 'del-rules':
        #         self.delete_rule_resource(rule)

        return True

    def action_resource(self, task, *args, **kvargs):
        """Send action to resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        compute_zone = self.get_config("computeZone")
        container = self.get_config("container")

        # create new rules
        action = kvargs.get("action", None)
        rules = kvargs.get("rules", [])
        for rule in rules:
            if action == "add-rules":
                self.create_resource_rule(task, compute_zone, rule, container, reserved=False)
            elif action == "del-rules":
                self.delete_rule_resource(task, rule)

        return True

    def patch_resource(self, task, *args, **kvargs):
        """Patch resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        rules = self.get_config("rules")
        compute_zone = self.get_config("computeZone")
        container = self.get_config("container")
        # uuid = self.instance.resource_uuid

        # create rules
        for rule in rules:
            rule_type = __RULE_GROUP_INGRESS__
            others = ["%s:%s" % (rule.get("source").get("type"), rule.get("source").get("value"))]
            if rule.get("source").get("value") == "<resource id of SecurityGroup>":
                rule_type = __RULE_GROUP_EGRESS__
                others = [
                    "%s:%s"
                    % (
                        rule.get("destination").get("type"),
                        rule.get("destination").get("value"),
                    )
                ]
            others[0] = others[0].replace("<resource id of SecurityGroup>", self.instance.resource_uuid)

            service = rule.get("service")
            if service.get("protocol") == "*":
                service = "*:*"
            else:
                service = "%s:%s" % (service.get("protocol"), service.get("port"))

            res = self.list_rule_resources(others, service, rule_type)

            if len(res) == 0:
                # TODO check me  modificato richiamo probabilmente errato
                self.create_resource_rule(task, compute_zone, rule, container, reserved=True)
            elif res[0]["state"] == "ERROR":
                # delete ERROR rule
                self.delete_rule_resource(task, res)
                # recreate rule
                # TODO check me  modificato richiamo probabilmente errato
                self.create_resource_rule(task, compute_zone, rule, container, reserved=True)
            else:
                self.logger.warning("Rule %s already exists" % rule)

        return True

    def list_rule_resources(self, others, service, rule_type):
        """List compute rules

        :param others:
        :param service: rule service
        :param rule_type: __RULE_GROUP_EGRESS__ or __RULE_GROUP_INGRESS__
        :return: rules
        """
        all_rules = []
        for other in others:
            if rule_type == __RULE_GROUP_EGRESS__:
                source = "SecurityGroup:%s" % self.instance.resource_uuid
                dest = other
            else:
                source = other
                dest = "SecurityGroup:%s" % self.instance.resource_uuid

            data = {"source": source, "destination": dest, "service": service}
            uri = "/v1.0/nrs/provider/rules"
            data = urlencode(data)
            rules = self.controller.api_client.admin_request("resource", uri, "get", data=data).get("rules", [])
            all_rules.extend(rules)
        return all_rules

    def check_rule_config_allowed(self, source, dest, protocol, ports):
        """Check rule_config are allowed by security group acl

        :param source: acl source. Can be *:*, Cidr:<>, Sg:<>
        :param dest: destination security group resource id
        :param protocol: acl protocol. Can be *:*, 7:*, 9:0 or tcp:*
        :param ports: comma separated list of ports, single port or ports interval
        :return: rules
        """
        data = {"source": source, "protocol": protocol, "ports": ports}
        uri = "/v1.0/nrs/provider/security_groups/%s/acls/check" % dest
        data = urlencode(data)
        res = self.controller.api_client.admin_request("resource", uri, "get", data=data).get(
            "security_group_acl_check", False
        )
        if res is False:
            raise ApiManagerError("Rule does not satisfy security group acl. It can not be created.")

    def list_all_resource_rules(self):
        """List all compute rules of the security group

        :return: rules
        """
        compute_zone = self.get_config("computeZone")

        data = {"parent_list": compute_zone, "size": -1}
        uri = "/v1.0/nrs/provider/rules"
        data = urlencode(data)
        rules = self.controller.api_client.admin_request("resource", uri, "get", data=data).get("rules", [])
        res = []
        for rule in rules:
            rule_conf = rule.get("attributes", {}).get("configs", {})
            source = rule_conf.get("source", {})
            dest = rule_conf.get("destination", {})
            if (dest.get("type") == "SecurityGroup" and dest.get("value") == self.instance.resource_uuid) or (
                source.get("type") == "SecurityGroup" and source.get("value") == self.instance.resource_uuid
            ):
                res.append(rule)
        self.logger.debug("Get security group %s rules: %s" % (self.instance.uuid, truncate(res)))
        return res

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        rules = self.list_all_resource_rules()

        # delete rules
        for rule in rules:
            self.delete_rule_resource(task, rule)

        return ApiServiceTypePlugin.delete_resource(self, task, *args, **kvargs)

    def delete_rule_resource(self, task, rule):
        """Delete security group rule resources

        :param task: celery task reference
        :param rule: compute zone rule uuid
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        try:
            uri = "/v1.0/nrs/provider/rules/%s" % rule.get("uuid")
            res = self.controller.api_client.admin_request("resource", uri, "delete")
            taskid = res.get("taskid", None)
            self.logger.debug("Delete compute zone rule: %s - start" % rule)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.message)
            raise ApiManagerError(ex.message)

        # set resource uuid
        if taskid is not None:
            self.wait_for_task(taskid, delta=4, maxtime=600, task=task)
            self.logger.debug("Delete compute zone rule: %s - stop" % rule)

        return True


class ApiNetworkSubnet(AsyncApiServiceTypePlugin):
    plugintype = "NetworkSubnet"
    objname = "subnet"

    class state_enum(object):
        """enumerate state name esposed by api"""

        pending = "pending"
        available = "available"
        deregistered = "deregistered"
        transient = "transient"
        error = "error"
        unknown = "unknown"

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
        info = ApiServiceTypePlugin.info(self)
        info.update({})
        return info

    @staticmethod
    def customize_list(controller: ServiceController, entities: List, *args, **kvargs) -> List:
        # da capire
        # def customize_list(controller: ServiceController, entities: List[ApiNetworkSubnet], *args, **kvargs) \
        #         -> List[ApiNetworkSubnet]:
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
        compute_service_idx = controller.get_service_instance_idx(ApiNetworkService.plugintype, index_key="account_id")
        vpc_idx = controller.get_service_instance_idx(ApiNetworkVpc.plugintype)

        # get resources
        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.vpc_idx = vpc_idx
            entity.account = account_idx.get(account_id)
            entity.compute_service = compute_service_idx.get(account_id)
            entity.vpc = vpc_idx.get(entity.instance.get_parent_id())

        # assign resources
        for entity in entities:
            entity.resource = None

        return entities

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.account = self.controller.get_account(str(self.instance.account_id))
        self.vpc = self.controller.get_service_instance(self.instance.get_parent_id())

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: self.state_enum.pending,  # 'pending',
            SrvStatusType.ACTIVE: self.state_enum.available,  # 'available',
            SrvStatusType.DELETED: self.state_enum.deregistered,  # 'deregistered',
            SrvStatusType.DRAFT: self.state_enum.transient,  # 'transient',
            SrvStatusType.ERROR: self.state_enum.error,  # 'error'
        }
        return mapping.get(state, self.state_enum.unknown)

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        inst_service = self.instance
        instance_item = {}

        instance_item["assignIpv6AddressOnCreation"] = False
        instance_item["availableIpAddressCount"] = None
        instance_item["defaultForAz"] = True
        instance_item["mapPublicIpOnLaunch"] = False
        instance_item["tagSet"] = []

        if self.get_config("site") is not None:
            instance_item["availabilityZone"] = self.get_config("site")
            instance_item["cidrBlock"] = self.get_config("cidr")

        instance_item["subnetId"] = inst_service.uuid
        instance_item["vpcId"] = self.vpc.uuid
        instance_item["state"] = self.state_mapping(inst_service.status)
        instance_item["ownerId"] = self.account.uuid
        # custom params
        instance_item["nvl-name"] = inst_service.name
        instance_item["nvl-vpcName"] = self.vpc.name
        instance_item["nvl-subnetOwnerAlias"] = self.account.name
        instance_item["nvl-subnetOwnerId"] = self.account.uuid

        return instance_item

    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        data = self.get_config("subnet")
        dns_searches = self.get_config("dns_search")
        vpc_id = data.get("VpcId")
        zone = data.get("AvailabilityZone")
        cidr = data.get("CidrBlock")
        dns_search = None
        if dns_searches is not None:
            dns_search = dns_searches.get(zone)

        self.set_config("cidr", cidr)
        self.set_config("site", zone)

        # get vpc
        vpc = self.controller.get_service_type_plugin(vpc_id, plugin_class=ApiNetworkVpc)
        tenancy = vpc.get_tenancy()

        if tenancy == "default":
            params["resource_params"] = {}
        elif tenancy == "dedicated":
            params["resource_params"] = {
                "vpc": {"id": vpc.resource_uuid, "tenancy": tenancy},
                "cidr": cidr,
                "dns_search": dns_search,
                # 'zabbix_proxy':,
                "dns_nameservers": ["10.103.48.1", "10.103.48.2"],
                "availability_zone": zone,
                "orchestrator_tag": "default",
            }
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    def get_cidr(self):
        """Get subnet cidr"""
        cidr = self.get_config("subnet").get("CidrBlock", None)
        return cidr

    #
    # resource client method
    #
    def list_resources(self, zones=[], uuids=[], tags=[], page=0, size=-1):
        """Get resource info

        :return: Dictionary with resources info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        return []

    def create_resource(self, task, *args, **kvargs):
        """Create resource. Do nothing. Use existing resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        vpc = args[0].pop("vpc", {})

        if vpc.get("tenancy", None) == "dedicated":
            data = {"private": [args[0]]}
            try:
                uri = "/v2.0/nrs/provider/vpcs/%s/network" % vpc.get("id")
                res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
                uuid = res.get("uuid", None)
                taskid = res.get("taskid", None)
                self.logger.debug("Create subnet to vpc %s" % uuid)
            except ApiManagerError as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.value)
                raise
            except Exception as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.message)
                raise ApiManagerError(ex.message)

            # set resource uuid
            if uuid is not None and taskid is not None:
                self.set_resource(uuid)
                self.update_status(SrvStatusType.PENDING)
                self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
                self.update_status(SrvStatusType.CREATED)
                self.logger.debug("Update compute subnet resources: %s" % uuid)

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource. Do nothing.

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        if self.resource_uuid is not None:
            data = self.get_config("subnet")
            vpc_id = data.get("VpcId")
            zone = data.get("AvailabilityZone")
            cidr = data.get("CidrBlock")

            vpc = self.controller.get_service_type_plugin(vpc_id, plugin_class=ApiNetworkVpc)

            data = {
                "private": [
                    {
                        "cidr": cidr,
                        "availability_zone": zone,
                        "orchestrator_tag": "default",
                    }
                ]
            }
            try:
                uri = "/v2.0/nrs/provider/vpcs/%s/network" % vpc.resource_uuid
                res = self.controller.api_client.admin_request("resource", uri, "delete", data=data)
                uuid = res.get("uuid", None)
                taskid = res.get("taskid", None)
                self.logger.debug("Remove subnet from vpc %s" % uuid)
            except ApiManagerError as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.value)
                raise
            except Exception as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.message)
                raise ApiManagerError(ex.message)

            # set resource uuid
            if uuid is not None and taskid is not None:
                self.set_resource(uuid)
                self.update_status(SrvStatusType.PENDING)
                self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
                self.update_status(SrvStatusType.CREATED)
                self.logger.debug("Update compute subnet resources: %s" % uuid)


class ApiNetworkElasticIp(AsyncApiServiceTypePlugin):
    plugintype = "ElasticIp"
    objname = "elasticip"

    class state_enum(object):
        """enumerate state name esposed by api"""

        unknown = "unknown"
        pending = "pending"
        available = "available"
        deregistered = "deregistered"
        transient = "transient"
        error = "error"

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
        info = ApiServiceTypePlugin.info(self)
        info.update({})
        return info

    def state_mapping(self, state):
        mapping = {
            SrvStatusType.PENDING: self.state_enum.pending,  # 'pending',
            SrvStatusType.ACTIVE: self.state_enum.available,  # 'available',
            SrvStatusType.DELETED: self.state_enum.deregistered,  # 'deregistered',
            SrvStatusType.DRAFT: self.state_enum.transient,  # 'transient',
            SrvStatusType.ERROR: self.state_enum.error,  # 'error'
        }
        return mapping.get(state, self.state_enum.unknown)

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

        # get resources
        for entity in entities:
            account_id = str(entity.instance.account_id)
            entity.account = account_idx.get(account_id)

        return entities

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.account = self.controller.get_account(str(self.instance.account_id))

    def aws_info(self):
        """Get info as required by aws api

        :return:
        """
        if self.resource is None:
            self.resource = {}

        # get child subnets
        subnets = self.instance.get_child_instances(plugintype=ApiNetworkSubnet.plugintype)

        instance_item = {}
        instance_item["vpcId"] = self.instance.uuid
        instance_item["state"] = self.state_mapping(self.instance.status)
        instance_item["cidrBlock"] = self.get_cidr()

        instance_item["cidrBlockAssociationSet"] = []
        instance_item["ipv6CidrBlockAssociationSet"] = []
        for subnet in subnets:
            cidr_block_association_set = {}
            cidr_block_association_set["associationId"] = subnet.uuid
            cidr_block_association_set["cidrBlock"] = subnet.get_main_config().get_json_property("cidr")
            cidr_block_association_set["cidrBlockState"] = {
                "state": "associated",
                "statusMessage": "",
            }
            instance_item["cidrBlockAssociationSet"].append(cidr_block_association_set)

            # ipv6_cidr_block_association_set = {}
            # ipv6_cidr_block_association_set['associationId'] = subnet.uuid
            # ipv6_cidr_block_association_set['ipv6CidrBlock'] = ''
            # ipv6_cidr_block_association_set['ipv6CidrBlockState'] = {'state': 'associated', 'statusMessage': ''}
            # instance_item['ipv6CidrBlockAssociationSet'].append(ipv6_cidr_block_association_set)

        instance_item["dhcpOptionsId"] = ""
        instance_item["instanceTenancy"] = self.get_tenancy()
        instance_item["isDefault"] = False
        instance_item["tagSet"] = []

        instance_item["ownerId"] = self.account.uuid
        # custom params
        instance_item["nvl-name"] = self.instance.name
        instance_item["nvl-vpcOwnerAlias"] = self.account.name
        instance_item["nvl-vpcOwnerId"] = self.account.uuid
        instance_item["nvl-resourceId"] = self.instance.resource_uuid

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
            "compute.networks": 1,
        }

        # get container
        container_id = self.get_config("container")
        compute_zone = self.get_config("computeZone")
        vpc_config = self.get_config("vpc")
        tenancy = vpc_config.get("InstanceTenancy", "default")
        cidr = vpc_config.get("CidrBlock", None)

        # check quotas
        self.check_quotas(compute_zone, quotas)

        # select cidr
        if cidr is None:
            cidr = self.get_config("cidr")

        # select vpc type
        if tenancy == "default":
            vpc_type = "shared"
            networks = self.get_config("networks")
        elif tenancy == "dedicated":
            vpc_type = "private"
            networks = None

        name = "%s-%s" % (self.instance.name, id_gen(length=8))

        data = {
            "container": container_id,
            "name": name,
            "desc": self.instance.desc,
            "compute_zone": compute_zone,
            "networks": networks,
            "type": vpc_type,
            "cidr": cidr,
        }

        params["resource_params"] = data
        self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    #
    # resource client method
    #
    @trace(op="view")
    def list_resources(self, zones=[], uuids=[], tags=[], page=0, size=-1):
        """Get resources info

        :return: Dictionary with resources info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {"size": size, "page": page}
        if len(zones) > 0:
            data["parent_list"] = ",".join(zones)
        if len(uuids) > 0:
            data["uuids"] = ",".join(uuids)
        if len(tags) > 0:
            data["tags"] = ",".join(tags)
        self.logger.debug("list_vpc_resources %s" % data)

        instances = self.controller.api_client.admin_request(
            "resource", "/v2.0/nrs/provider/vpcs", "get", data=urlencode(data)
        ).get("instances", [])
        self.logger.debug("Get compute vpc resources: %s" % truncate(instances))
        return instances

    @trace(op="insert")
    def create_resource(self, task, *args, **kvargs):
        """Create resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        vpc_type = args[0]["type"]
        networks = args[0].pop("networks", None)

        data = {"vpc": args[0]}
        try:
            uri = "/v2.0/nrs/provider/vpcs"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create resource: %s" % uuid)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.message)
            raise ApiManagerError(ex.message)

        # set resource uuid
        if uuid is not None and taskid is not None:
            self.set_resource(uuid)
            self.update_status(SrvStatusType.PENDING)
            self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
            self.update_status(SrvStatusType.CREATED)
            self.logger.debug("Update compute vpc resources: %s" % uuid)

        # add shared network to vpc
        if vpc_type == "shared":
            try:
                data = {"site": [{"network": n} for n in networks]}
                uri = "/v2.0/nrs/provider/vpcs/%s/network" % uuid
                res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
                uuid = res.get("uuid", None)
                taskid = res.get("taskid", None)
                self.logger.debug("Append site networks to vpc %s - start" % uuid)
            except ApiManagerError as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.value)
                raise
            except Exception as ex:
                self.logger.error(ex, exc_info=True)
                self.update_status(SrvStatusType.ERROR, error=ex.message)
                raise ApiManagerError(ex.message)

            # set resource uuid
            if uuid is not None and taskid is not None:
                self.set_resource(uuid)
                self.update_status(SrvStatusType.PENDING)
                self.wait_for_task(taskid, delta=2, maxtime=180, task=task)
                self.update_status(SrvStatusType.CREATED)
                self.logger.debug("Append site networks to vpc %s - end" % uuid)

        return uuid

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        return ApiServiceTypePlugin.delete_resource(self, *args, **kvargs)


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
        controller: ServiceController = self.controller
        _links, total = controller.get_links(type="tg-hm", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Health monitor %s is in use, cannot be deleted" % self.instance.uuid)

        return params


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

        controller: ServiceController = self.controller

        # check is used
        links, total = controller.get_links(type="lb-tg", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Target group %s is in use, cannot be deleted" % self.instance.uuid)

        links, tot = controller.get_links(start_service=self.instance.oid, type="tg-t")
        for link in links:
            # remove reference to target group in balanced target
            link_info = link.info()
            end_service_uuid = dict_get(link_info, "details.end_service.uuid")
            end_service_inst = controller.get_service_instance(end_service_uuid)
            target_groups = end_service_inst.get_config("instance.nvl-targetGroups")
            target_groups.remove(self.instance.uuid)
            if not target_groups:
                target_groups = None
            end_service_inst.set_config("instance.nvl-targetGroups", target_groups)
            # delete link to target
            link.expunge()

        # remove link to health monitor
        links, tot = controller.get_links(start_service=self.instance.oid, type="tg-hm")
        if tot == 1:
            links[0].expunge()

        # delete custom health monitor instance only
        try:
            type_plugin = controller.get_service_type_plugin(hm_id)
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
        controller: ServiceController = self.controller
        _links, total = controller.get_links(type="lb-li", end_service=self.instance.oid)
        if total != 0:
            raise ApiManagerError("Listener %s is in use, cannot be deleted" % self.instance.uuid)

        return params


class ApiNetworkLoadBalancer(AsyncApiServiceTypePlugin):
    plugintype = "NetworkLoadBalancer"
    objname = "load_balancer"

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

        controller: ServiceController = self.controller

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

        self.controller: ServiceController
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

        controller: ServiceController = self.controller

        # get listener and check it is active
        listener_inst: ApiServiceInstance = controller.get_service_instance(listener_id)
        listener_plugin: ApiNetworkListener = listener_inst.get_service_type_plugin()
        listener_info = listener_plugin.aws_info()

        # get target group and check it is active
        target_group_inst: ApiServiceInstance = controller.get_service_instance(target_group_id)
        target_group_plugin: ApiNetworkTargetGroup = target_group_inst.get_service_type_plugin()
        target_group_info = target_group_plugin.aws_info()

        # get health monitor if exists
        health_monitor_id = dict_get(target_group_info, "attachmentSet.HealthMonitor.healthMonitorId")
        health_monitor_info = None
        if health_monitor_id is not None:
            health_monitor_inst: ApiServiceInstance = controller.get_service_instance(health_monitor_id)
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

        controller: ServiceController = self.controller

        try:
            # remove link to listener
            links, _tot = controller.get_links(start_service=self.instance.oid, type="lb-li")
            links[0].expunge()
            if not no_linked_objs:
                # delete listener instance
                type_plugin = controller.get_service_type_plugin(li_id)
                type_plugin.delete()
        except Exception:
            # go ahead anyway
            pass

        try:
            # remove link to target group
            links, _tot = controller.get_links(start_service=self.instance.oid, type="lb-tg")
            links[0].expunge()
            if not no_linked_objs:
                # delete target group instance
                type_plugin = controller.get_service_type_plugin(tg_id)
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
