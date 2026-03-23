#!/usr/bin/env python
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2026 CSI-Piemonte

from beehive.common.apimanager import ApiView

from typing import TYPE_CHECKING

from .create import CreateLbaas
from .delete import DeleteLbaas
from .get import GetLbaas
from .list import ListLbaas, AccountListLbaas
from .update import UpdateLbaas, PatchLbaas
from .template import LbaasTemplates, AccountLbaasTemplates
from .flavour import LbaasFlavours, AccountLbaasFlavours
from .test import TestLbaas
class NetworkLbaasAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/lbaas"
        rules = [
            ("%s" % base, "GET", ListLbaas, {}),
            ("%s" % base, "POST", CreateLbaas, {}),
            ("%s/templates" % base, "GET", LbaasTemplates, {}),
            ("%s/flavours" % base, "GET", LbaasFlavours, {}),
            ("%s/<oid>" % base, "GET", GetLbaas, {}),
            ("%s/<oid>/test" % base, "GET", TestLbaas, {}),
            ("%s/<oid>" % base, "DELETE", DeleteLbaas, {}),
            ("%s/<oid>" % base, "PUT", UpdateLbaas, {}),
            ("%s/<oid>" % base, "PATCH", PatchLbaas, {}),
            ("%s/account/<oid>/network/lbaas" % module.base_path, "GET", AccountListLbaas, {}),
            ("%s/account/<oid>/network/lbaas_templates" % module.base_path, "GET", AccountLbaasTemplates, {}),
            ("%s/account/<oid>/network/lbaas_flavours" % module.base_path, "GET", AccountLbaasFlavours, {}),
            
            
            # ("%s/<oid>/configs" % base, "GET", ListConfiguration, {}),
            # ("%s/<oid>/configs" % base, "PUT", AddConfiguration, {}),
            # ("%s/<oid>/configs/<config>" % base, "GET",  GetConfiguration, {}),
            # ("%s/<oid>/configs/<config>" % base, "DELETE",  DeleteConfiguration, {}),
            # ("%s/<oid>/configs/<config>/backend" % base, "GET",  ListBackend, {}),
            # ("%s/<oid>/configs/<config>/backend" % base, "DELETE",  DeleteConfigurationBackend, {}),
            # ("%s/<oid>/configs/<config>/backend" % base, "POST", AddConfigurationBackend, {}),

        ]

        ApiView.register_api(module, rules, **kwargs)
