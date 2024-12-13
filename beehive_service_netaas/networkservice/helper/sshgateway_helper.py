# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 Regione Piemonte
# (C) Copyright 2018-2024 CSI-Piemonte

from logging import getLogger
from itertools import groupby
from typing import AbstractSet
from beehive_service.plugins.databaseservice.controller import (
    ApiDatabaseServiceInstance,
)
from beehive_service.plugins.computeservice.controller import (
    ApiComputeInstance,
)


def to_ranges(in_set):
    """
    from set to ranges
    """
    iterable = sorted(in_set)
    for _key, group in groupby(enumerate(iterable), lambda t: t[1] - t[0]):
        group = list(group)
        yield group[0][1], group[-1][1]


class SshGatewayHelperError(Exception):
    """
    :param value: error description
    """

    def __init__(self, value):
        self.value = str(value)
        Exception.__init__(self, self.value)

    def __repr__(self):
        return f"SshGatewayHelperError: {self.value}"

    def __str__(self):
        return f"{self.value}"


class SshGwType:
    """enumerate ssh gateway type"""

    DBAAS = "gw_dbaas"
    CPAAS = "gw_cpaas"

    @staticmethod
    def validate(string_value):
        """
        True if string_value is among the enumerated values
        False otherwise
        """
        if string_value not in (SshGwType.DBAAS, SshGwType.CPAAS):
            return False
        return True


class SshGatewayHelper:
    """
    helper class for ssh gateway service module
    """

    def __init__(self, controller=None):
        """Create a ssh gw helper

        :param controller: service controller
        """
        self.logger = getLogger(self.__class__.__module__ + "." + self.__class__.__name__)
        self.controller = controller

    def _parse_port_list(self, port_list, in_set: AbstractSet[int] = None, negative_mode=False):
        """
        from list of ports to set of ports
        :param in_set: input port set to update. created if not given.
        :param port_list: list of elements
        each element can be in the form:
        - port e.g. 22
        - port range e.g. 1-100
        :returns: set() of int elements representing the single ports
        """
        if in_set and isinstance(in_set, set):
            parsed_ports_set = in_set
        else:
            parsed_ports_set = set()

        if port_list is not None:
            for elem in port_list:
                port1_port2 = elem.split("-")
                try:
                    port1 = int(port1_port2[0])
                    port2 = int(port1_port2[1]) if len(port1_port2) > 1 else None
                except ValueError:
                    self.logger.error("Ignored invalid int value")
                    continue

                if port2 is None:
                    if port1 is None:
                        self.logger.error("Ignored invalid value: %s", elem)
                    else:
                        if negative_mode:
                            parsed_ports_set.discard(port1)
                        else:
                            parsed_ports_set.add(port1)
                else:
                    if port2 > port1:
                        tmp_set = set(x for x in range(port1, port2 + 1))
                        if negative_mode:
                            parsed_ports_set.difference_update(tmp_set)
                        else:
                            parsed_ports_set.update(tmp_set)
                    else:
                        self.logger.error("Ignored invalid value: %s", elem)

        return parsed_ports_set

    def check_get_parameters(self, gw_type, dest_uuid, allowed_ports=None, forbidden_ports=None):
        """checks parameters are coherent with each other
        :return: Tuple dest_account, parsed_port_set
        :raises SshGatewayHelperError: raise :class:`.SshGatewayHelperError`
        """

        if gw_type is None:
            raise SshGatewayHelperError("gw_type parameter missing.")

        gw_type = gw_type.lower()
        if SshGwType.validate(gw_type) is False:
            raise SshGatewayHelperError("Invalid ssh gateway type.")

        if dest_uuid is None:
            raise SshGatewayHelperError("dest_uuid parameter missing.")

        dest_plugin_type = self.controller.get_service_type_plugin(dest_uuid)
        if dest_plugin_type is None:
            raise SshGatewayHelperError(
                "Destination not found or view permission on destination not given to current user."
            )

        # verify type and destination are compatible
        if (gw_type == SshGwType.DBAAS and not (isinstance(dest_plugin_type, ApiDatabaseServiceInstance))) or (
            gw_type == SshGwType.CPAAS and not (isinstance(dest_plugin_type, ApiComputeInstance))
        ):
            raise SshGatewayHelperError("Incompatible gw_type and dest_id parameters.")

        dest_account = dest_plugin_type.get_account()
        if dest_account is None:
            raise SshGatewayHelperError("Unable to determine account of destination object.")

        if gw_type == SshGwType.DBAAS:
            db_port = dest_plugin_type.aws_info().get("Endpoint", {}).get("Port", None)
            if db_port is None:
                raise SshGatewayHelperError("Unable to determine database port.")

            db_port = int(db_port)
            parsed_ports_set = [[db_port, db_port]]
        else:
            parsed_ports_set = self._parse_port_list(allowed_ports)
            parsed_ports_set = self._parse_port_list(forbidden_ports, parsed_ports_set, True)
            parsed_ports_set = list(to_ranges(parsed_ports_set))  # transform set to list of from-to values

        if len(parsed_ports_set) == 0:
            raise SshGatewayHelperError("No valid ports found.")

        return (dest_account, parsed_ports_set)
