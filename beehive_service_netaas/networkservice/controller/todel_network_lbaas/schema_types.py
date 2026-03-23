# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from typing import TypedDict, List, Union


from flasgger import Schema
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf
from beehive_service_netaas.networkservice.validation import validate_network

#SwaggerTAG="networkservice"
