# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

import ipaddress
from marshmallow import ValidationError


def validate_network(cidrblk: str):
    # or bool( not cidrblk):
    if cidrblk is None:
        return

    try:
        ipaddress.ip_network(cidrblk)
    except ValueError as ex:
        raise ValidationError(str(ex)) from ex
