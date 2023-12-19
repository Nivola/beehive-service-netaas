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


class NetworkSiteToSiteVpnAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/sitetositevpn"
        rules = [
            # ('%s/describeinternetgateways' % base, 'GET', DescribeInternetGateways, {}),
            # ('%s/createinternetgateway' % base, 'POST', CreateInternetGateway, {}),
            # ('%s/deleteinternetgateway' % base, 'DELETE', DeleteInternetGateway, {}),
            # ('%s/attachinternetgateway' % base, 'PUT', AttachInternetGateway, {}),
            # ('%s/detachinternetgateway' % base, 'PUT', DetachInternetGateway, {}),
            # ('%s/describeegressonlyinternetgateways' % base, 'GET', DescribeEgressonlyinternetgateways, {}),
            # ('%s/createegressonlyinternetgateway' % base, 'POST', CreateEgressonlyinternetgateway, {}),
            # ('%s/deleteegressonlyinternetgateway' % base, 'DELETE', DeleteEgressonlyinternetgateway, {}),
        ]

        ApiView.register_api(module, rules, **kwargs)
