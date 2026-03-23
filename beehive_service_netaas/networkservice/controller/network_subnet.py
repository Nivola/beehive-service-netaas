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
# from beehive_service.controller import ServiceController

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
# import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController

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
        from .network_service import ApiNetworkService
        from .network_vpc import ApiNetworkVpc
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
        from .network_vpc import ApiNetworkVpc
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

            from .network_vpc import ApiNetworkVpc
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

