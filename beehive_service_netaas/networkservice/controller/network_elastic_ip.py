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
from beehive_service.controller import ServiceController

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
from .network_subnet import ApiNetworkSubnet
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController

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

