# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2023 CSI-Piemonte

from flasgger import Schema
from beecell.simple import id_gen
from beehive.common.apimanager import ApiView, SwaggerApiView
from beehive.common.data import operation
from beehive_service.views import ServiceApiView
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from beehive_service_netaas.networkservice import ApiNetworkGateway, ApiNetworkService


class NetworkClientVpnAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/clientvpn"
        rules = [
            # ('%s/createclientvpnendpoint' % base, 'POST', CreateClientVpnEndpoint, {}),
            # ('%s/describeclientvpnendpoints' % base, 'GET', DescribeClientVpnEndpoints, {}),
            # ('%s/modifyclientvpnendpoint' % base, 'PUT', ModifyClientVpnEndpoint, {}),
            # ('%s/deleteclientvpnendpoint' % base, 'DELETE', DeleteClientVpnEndpoint, {}),
            #
            # # ('%s/applySecurityGroupsToClientvpntargetnetwork' % base, 'GET', ApplySecurityGroupsToClientVpnTargetNetwork, {}),
            # ('%s/associateclientvpntargetnetwork' % base, 'POST', AssociateClientVpnTargetNetwork, {}),
            # ('%s/disassociateclientvpntargetnetwork' % base, 'DELETE', DisassociateClientVpnTargetNetwork, {}),
            # ('%s/describeclientvpntargetnetworks' % base, 'GET', DescribeClientVpnTargetNetworks, {}),
            #
            # ('%s/authorizeclientvpningress' % base, 'POST', AuthorizeClientVpnIngress, {}),
            # ('%s/revokeclientvpningress' % base, 'DELETE', RevokeClientVpnIngress, {}),
            # ('%s/describeclientVpnAuthorizationRules' % base, 'GET', DescribeClientVpnAuthorizationRules, {}),
            #
            # ('%s/createclientvpnroute' % base, 'POST', CreateClientVpnRoute, {}),
            # ('%s/deleteclientvpnroute' % base, 'DELETE', DeleteClientVpnRoute, {}),
            # ('%s/describeclientvpnroutes' % base, 'GET', DescribeClientVpnRoutes, {}),
            #
            # ('%s/terminateClientVpnConnections' % base, 'GET', TerminateClientVpnConnections, {}),
            # ('%s/terminateClientVpnConnections' % base, 'DELETE', TerminateClientVpnConnections, {}),
            #
            # # custom
            # ('%s/createuser' % base, 'POST', CreateUser, {}),
            # ('%s/deleteuser' % base, 'DELETE', DeleteUser, {}),
            # ('%s/describeusers' % base, 'GET', DescribeUsers, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
