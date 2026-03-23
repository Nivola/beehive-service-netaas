# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from __future__ import annotations
from beecell.types.type_string import str2bool

from typing import List, TYPE_CHECKING

from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController


from .network_health_monitor import  ApiNetworkHealthMonitor
from .network_listener import  ApiNetworkListener
from .network_load_balancer import  ApiNetworkLoadBalancer
from .network_service import  ApiNetworkService
from .network_target_group import  ApiNetworkTargetGroup
from .network_vpc import ApiNetworkVpc
from .network_gateway import ApiNetworkGateway
from .network_elastic_ip import  ApiNetworkElasticIp
from .network_security_group import  ApiNetworkSecurityGroup
from .network_site_to_site_vpn import  ApiNetworkSiteToSiteVpn
from .network_subnet import  ApiNetworkSubnet
from .ssh_gateway import ApiSshGateway
from .network_lbaas import ApiNetworkLbaasInstance

ApiNetworkService.class_child_classes = [
            ApiNetworkGateway,
            ApiNetworkVpc,
            ApiNetworkHealthMonitor,
            ApiNetworkTargetGroup,
            ApiNetworkListener,
            ApiNetworkLoadBalancer,
            ApiNetworkLbaasInstance
            # ApiNetworkSubnet,
            # ApiNetworkSecurityGroup
        ]
