# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from beehive_service_netaas.networkservice.controller import (
    ApiNetworkGateway,
    ApiNetworkService,
    ApiNetworkHealthMonitor,
    ApiNetworkTargetGroup,
    ApiNetworkListener,
    ApiNetworkLoadBalancer,
    ApiSshGateway,
    ApiNetworkLbaasInstance
)
from beehive_service_netaas.networkservice.views import NetworkServiceAPI
from beehive_service_netaas.networkservice.views.gateway import NetworkGatewayAPI
from beehive_service_netaas.networkservice.views.loadbalancer import (
    NetworkLoadBalancerAPI,
)
from beehive_service_netaas.networkservice.views.securitygroup import (
    NetworkSecurityGroupAPI,
)
from beehive_service_netaas.networkservice.views.subnet import NetworkSubnetAPI
from beehive_service_netaas.networkservice.views.vpc import NetworkVpcAPI
from beehive_service_netaas.networkservice.views.sshgateway import NetworkSshGatewayAPI
from beehive_service_netaas.networkservice.views.lbaas import NetworkLbaasAPI

class NetworkServicePlugin(object):
    def __init__(self, module):
        self.module = module
        self.st_plugins = [
            ApiNetworkService,
            ApiNetworkGateway,
            ApiNetworkHealthMonitor,
            ApiNetworkTargetGroup,
            ApiNetworkListener,
            ApiNetworkLoadBalancer,
            ApiSshGateway,
            ApiNetworkLbaasInstance
        ]

    def init(self):
        for srv in self.st_plugins:
            service = srv(self.module.get_controller())
            service.init_object()

    def register(self):
        apis = [
            NetworkServiceAPI,
            NetworkGatewayAPI,
            NetworkLoadBalancerAPI,
            NetworkVpcAPI,
            NetworkSubnetAPI,
            NetworkSecurityGroupAPI,
            NetworkSshGatewayAPI,
            NetworkLbaasAPI,
        ]
        self.module.set_apis(apis)
