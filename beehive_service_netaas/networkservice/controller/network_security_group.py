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
from .network_vpc import ApiNetworkVpc
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController

class ApiNetworkSecurityGroup(AsyncApiServiceTypePlugin):
    plugintype = "NetworkSecurityGroup"
    objname = "securitygroup"
    class_child_classes = []
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

        self.rule_factory(rule_data, reserved=False)
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

