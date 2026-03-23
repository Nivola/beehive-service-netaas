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
# from urllib.parse import urlencode
# from beehive_service.model import SrvStatusType
from beecell.simple import (
    format_date,
    truncate,
    obscure_data,
    id_gen,
    dict_get,
    random_password,
)

from typing import List, TYPE_CHECKING
from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
# import ipaddress
if TYPE_CHECKING:
    from beehive_service.plugins.computeservice.controller import ServiceController

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

