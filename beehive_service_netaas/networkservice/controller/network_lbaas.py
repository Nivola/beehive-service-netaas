# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2026 CSI-Piemonte

from __future__ import annotations
from copy import deepcopy
import json

# from beecell.types.type_string import str2bool
from beehive.common.data import trace
from beehive.common.apimanager import ApiManagerError, ApiManagerWarning

from beecell.types.res.haproxy import (
    HaproxyConfigDict,
    FRONTEND_HTTP,
    FRONTEND_HTTPS,
    AclFqdnDict,
    FeBeDict,
    BeDict,
)

from beehive_service.entity.service_instance import ApiServiceInstance
from beehive_service.entity.service_type import (
    ApiServiceTypeContainer,
    ApiServiceTypePlugin,
    AsyncApiServiceTypePlugin,
)

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
from beehive_service.controller import ServiceController
from beehive_service.plugins.computeservice.controller import ApiComputeSubnet, ApiComputeSecurityGroup

# (
#     ApiComputeInstance
#     ApiComputeSecurityGroup,
#     ApiComputeVPC,
#     ApiComputeKeyPairsHelper,
#     ApiComputeService,
# )


from beehive_service.service_util import __RULE_GROUP_INGRESS__, __RULE_GROUP_EGRESS__
from json import dumps
import ipaddress
from .network_gateway import ApiNetworkGateway
from typing import List, TYPE_CHECKING, TypedDict, Union, Optional
from beecell.types.res.haproxy import HaproxyConfigDict, FRONTEND_HTTP, FRONTEND_HTTPS

if TYPE_CHECKING:
    from beecell.types.res.paas import CreatePaasParamRequestDict
    from beehive_service.plugins.computeservice.controller import ServiceController
    from beehive_service.controller.api_account import ApiAccount
    from .network_health_monitor import ApiNetworkHealthMonitor
    from beecell.types.bu.lbaas import (
        LbBackendDict,
        LbConfigurationDict,
        TagDict,
        TagSetDict,
        VpcSecurityGroupDict,
        LbaasFalvourDict,
        CustomizationDict,
        LbaasTemplateDict,
        LbaasDict,
        LbaasConfigDict,
    )


LbaasInstanceInfoDict = TypedDict(
    "LbaasInstanceInfoDict",
    {
        "ownerId": str,
        "nvl-ownerAlias": str,
        "loadBalancerId": str,
        "name": str,
        "state": str,
        "template": str,
        "availability_zone": str,
        "address": str,
        "security_group": str,
        "nvl-resourceId": str,
    },
)


class LbaasInstanceDetailDict(LbaasInstanceInfoDict):
    lbaas_config: LbConfigurationDict


class ApiNetworkLbaasInstance(AsyncApiServiceTypePlugin):
    plugintype = "NetworkLbaasInstance"
    objname = "lbaas"
    class_child_classes = []

    def __init__(self, *args, **kvargs):
        """ """
        ApiServiceTypePlugin.__init__(self, *args, **kvargs)
        if TYPE_CHECKING:
            self.account: ApiAccount
        self.child_classes = self.class_child_classes
        self._lbaasconfig: Optional[List[LbConfigurationDict]] = None

    def info(self):
        """Get object info
        :return: Dictionary with object info.
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        info = AsyncApiServiceTypePlugin.info(self)
        # info.update({"lbaas":self.lbaas_config})
        return info

    @property
    def user_pasword(self) -> str:
        if self.config is None:
            return "dummy"
        return self.config.json_cfg.get("user_pasword", "dummy")

    @user_pasword.setter
    def user_pasword(self, value: str):
        self.config.json_cfg["user_pasword"] = value

    @property
    def lbaas_config(self) -> Optional[List[LbConfigurationDict]]:
        if self._lbaasconfig is not None:
            return self._lbaasconfig

        if self.config is None:
            return None

        self._lbaasconfig = self.config.json_cfg.get("lbaasconfig", {})

        return self._lbaasconfig

    @lbaas_config.setter
    def lbaas_config(self, value: List[LbConfigurationDict]):
        self._lbaasconfig = value

        if self.config is None:
            return None

        self._lbaasconfig = self.config.json_cfg["lbaasconfig"] = self._lbaasconfig

        return self._lbaasconfig

    @staticmethod
    def customize_list(controller: ServiceController, entities, *args, **kvargs):
        """Post list function. Extend this function to execute some operation after entity was created. Used only for
        synchronous creation.

        :param controller: controller instance
        :param entities: list of entities
        :param args: custom params
        :param kvargs: custom params
        :return: None
        :raise ApiManagerError:
        """
        pass

    def post_get(self):
        """Post get function. This function is used in get_entity method. Extend this function to extend description
        info returned after query.

        :raise ApiManagerError:
        """
        self.controller: ServiceController
        self.account = self.controller.get_account(str(self.instance.account_id))
        if self.resource_uuid is not None:
            try:
                self.resource = self.get_resource()
            except Exception:
                self.resource = None
    
    def get_attr_from_res(self):
        """ get attribute from resouce
        """
        if self.resource is  None:
            self.post_get()
        
        az = self.resource.get("availability_zone", {}).get("name", "--")
        address = self.resource.get("listener", {}).get("address", "--")
        
        # self.instance.set_config("availability_zone", az)
        # self.instance.set_config("address", address)
        self.instance.set_config_properties( {"availability_zone": az, "address": address})


    @staticmethod
    def state_mapping(state):
        mapping = {
            SrvStatusType.PENDING: "pending",
            SrvStatusType.BUILDING: "building",
            SrvStatusType.CREATED: "building",
            SrvStatusType.ACTIVE: "available",
            SrvStatusType.DELETED: "deleted",
            SrvStatusType.DRAFT: "transient",
            SrvStatusType.ERROR: "error",
        }
        return mapping.get(state, "error")

    @trace(op="view")
    def get_resource(self, uuid=None):
        """Get resource info

        :param uuid: resource uuid [optional]
        :rtype: dict
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        resdict = None
        if uuid is None:
            uuid = self.instance.resource_uuid
        if uuid is not None:
            try:
                uri = "/v1.0/nrs/provider/paas/%s" % uuid
                resdict: dict = self.controller.api_client.admin_request("resource", uri, "get", data="").get("paas")
            except:
                self.logger.error("lbaas pass not found resurce %s lbaas %s ", uuid, self.instance.uuid)
                resdict = {}

        self.logger.debug("Got pass resource: %s" % truncate(resdict))
        return resdict

    def get_vip(self) -> Optional[str]:
        """Get load balancer frontend IP address

        :rtype: string, bool
        """
        if self.instance is not None:
            return self.instance.get_config("address")
        else:
            return "--"

    def __get_object_info(self, oid, plugin_class):
        try:
            type_plugin = self.controller.get_service_type_plugin(oid, plugin_class=plugin_class)
            info = type_plugin.aws_info()
        except Exception:
            info = {}
        return info

    def aws_info(self) -> LbaasInstanceInfoDict:
        return self.info()

    def list_info(self) -> LbaasInstanceInfoDict:
        """Get info as required by aws api

        :return:
        """
        if self.account is None:
            self.post_get()

        if self.resource is None:
            self.resource = {}

        # get load balancer virtual ip
        # vip, is_static = self.get_vip()

        instance_item: LbaasInstanceInfoDict = {}
        instance_item["ownerId"] = self.account.uuid
        instance_item["nvl-ownerAlias"] = self.account.name
        instance_item["loadBalancerId"] = self.instance.uuid
        instance_item["name"] = self.instance.name
        instance_item["state"] = self.state_mapping(self.instance.status)
        instance_item["template"] = self.instance.get_config("template")
        instance_item["availability_zone"] = self.instance.get_config("availability_zone")
        instance_item["address"] = self.instance.get_config("address")
        instance_item["address"] = self.instance.get_config("address")
        instance_item["security_group"] = self.instance.get_config("security_group_id")

        instance_item["nvl-resourceId"] = self.instance.resource_uuid

        return instance_item

    def lbaasdetail(self) -> LbaasInstanceDetailDict:
        res = self.list_info()
        res["lbaas_config"] = self.lbaas_config
        return res

    def testdetail(self) -> LbaasInstanceDetailDict:
        res = self.list_info()
        res["config"] = self.get_haproxy_config()
        return res

    def save_lbaas_configs(self):
        if self._lbaasconfig is not None:
            config = self.config
            config.json_cfg["lbaasconfig"] = self._lbaasconfig
            config.update(json_cfg=config.json_cfg)

    def add_lbaasconfig_item(self, newcfg: LbConfigurationDict) -> int:
        """Add or replace a new LB configiration

        Args:
            newcfg (LbConfigurationDict): _description_

        Returns:
            int: index  inserted
        """
        configurations = self.lbaas_config
        for i in range(len(configurations)):
            if configurations[i].get("alias") == newcfg.get("alias"):
                configurations[i] = newcfg
                return 1
        configurations.append(newcfg)
        return len(configurations)

    def get_lbaasconfig_item(self, alias: str) -> Union[LbConfigurationDict, None]:
        """Get  a LB configuration in man configuration by name(Alias)

        Args:
            newcfg (LbConfigurationDict): _description_

        Returns:
            int: index  inserted
        """
        configurations = self.lbaas_config
        for i in range(len(configurations)):
            if configurations[i].get("alias") == alias:
                return configurations[i]
        return None

    def delete_lbaasconfig_item(self, alias: str) -> bool:
        """dlete a configuration in man configuration by name(Alias)

        Args:
            newcfg (LbConfigurationDict): _description_

        Returns:
            int: index  inserted
        """

        configurations = self.lbaas_config
        for i in range(len(configurations)):
            if configurations[i].get("alias") == alias:
                del configurations[i]
                return True
        return False

    def get_haproxy_config(self) -> HaproxyConfigDict:
        result: HaproxyConfigDict = {
            "user_pwd": self.user_pasword,
            "description": f"{self.instance.name}",
            "nodename": self.instance.name,
            "certificate": [],  # List[CertiicateDict]
            "frontend_http": FRONTEND_HTTP,
            "frontend_https": FRONTEND_HTTPS,
            "http_acl_fqdn": {"acl": []},
            "https_acl_fqdn": {"acl": []},
            "use_backend_http": {"use": []},
            "use_backend_https": {"use": []},
            "haproxy_backend": [],
        }

        for index in range(len(self.lbaas_config)):
            conf = self.lbaas_config[index]
            cfg_name = conf.get("alias", f"{self.instance.name}_{str(index).zfill(3)}").replace(" ", "_")
            protocol = conf.get("protocol")
            if conf.get("certificate") is not None:
                result["certificate"].append(
                    {
                        "name": cfg_name,
                        "value": conf.get("certificate"),
                    }
                )
            acl: AclFqdnDict = {
                "name": f"is_{cfg_name}",  # is_toweb01-lbaas
                "fqdn": conf.get("fqdn"),  # toweb01.site05.nivolapiemonte.it
                # "condition": str # hdr(host)
            }
            http_fe_be: FeBeDict = {
                "name": f"http_{cfg_name}",
                "acl_name": f"is_{cfg_name}",
            }
            https_fe_be: FeBeDict = {
                "name": f"https_{cfg_name}",
                "acl_name": f"is_{cfg_name}",
            }
            https_backend: BeDict = {
                "name": f"https_{cfg_name}",
                "redirect_https": False,
                "server": [],
            }
            http_backend: BeDict = {
                "name": f"http_{cfg_name}",
                "server": [],
            }
            if bool(conf.get("RedirectHttp")):
                http_backend["redirect_https"] = "enabled"
                https_backend["redirect_https"] = "enabled"

            #    List[BeServerDict]
            for be in conf.get("backends"):
                habe = {
                    "name": be.get("name"),
                    "ip": be.get("ip"),
                    "port": be.get("port"),
                }
                # http_backend https_backend dipendono dal protocoolo del frontend (applicazione) non del backend
                # if be.get("protocol") == "http":
                if protocol == "http":
                    http_backend["server"].append(habe)
                else:
                    https_backend["server"].append(habe)

            if conf.get("stickySessions"):
                https_backend["cookie"] = f"{cfg_name}"
                http_backend["cookie"] = f"{cfg_name}"

            # if conf.get("protocol") == "http":
            if protocol == "http":
                result["http_acl_fqdn"]["acl"].append(acl)
            else:
                result["https_acl_fqdn"]["acl"].append(acl)
            # if
            if len(http_backend.get("server", [])) > 0:
                result["use_backend_http"]["use"].append(http_fe_be)
                result["haproxy_backend"].append(http_backend)
            if len(https_backend.get("server", [])) > 0:
                result["use_backend_https"]["use"].append(https_fe_be)
                result["haproxy_backend"].append(https_backend)

        ## remove unused parameters    certificate
        if len(result["certificate"]) == 0:
            result.pop("certificate")

        ## remove unused parameters http acl
        if len(result["http_acl_fqdn"]["acl"]) == 0:
            result.pop("http_acl_fqdn")
            result["frontend_http"] = {}

        ## remove unused parameters https acl
        if len(result["https_acl_fqdn"]["acl"]) == 0:
            result.pop("https_acl_fqdn")
            result["frontend_https"] = {}

        ## remove unused parameters http backend
        if len(result["use_backend_http"]["use"]) == 0:
            result.pop("use_backend_http")

        ## remove unused parameters https backend
        if len(result["use_backend_https"]["use"]) == 0:
            result.pop("use_backend_https")

        ## remove unused parameters backend
        if len(result["haproxy_backend"]) == 0:
            result.pop("haproxy_backend")

        # from beecell.debug import dbg
        # dbg(result)
        return {"p_config": result}

    #     class LbConfigurationDict(TypedDict):
    # Alias: str
    # Fqdn: str
    # Port: str
    # Ssl_termination: bool
    # Protocol: str
    # Certificate: str
    # StickySessions: bool
    # Backends: List[LbBackendDict]
    # WhiteList: List[str]
    def check_available_ip(self, vpc_resource_uuid: str, az: str, hypervisor: str):
        """Check aavailable ip
        raise exception if there are no aip available
        Args:
            vpc_resource_uuid (str): resurce uuid of the vpc
            az (str): Avalability Zone / site name
            hypervisor (str): hypervisor  vsphere, Opestack
        """
        # get vpc
        uri = f"/v2.0/nrs/provider/vpcs/{vpc_resource_uuid}/available-ips"
        data = {"orchestrator_type": hypervisor, "site": az}
        res = self.controller.api_client.admin_request("resource", uri, "get", data=data)
        available_ips = res.get("available_ips")
        if available_ips is not None:
            available_ips = int(available_ips)
            if available_ips <= 0:
                msg = f"""\
No more available ips on subnet for hypervisor {hypervisor} due to full allocation; \
consider requesting a new subnet or selecting another one.
        """
                raise ApiManagerError(msg)
        else:
            msg = "Failed to retrieve available IP count for subnet on %s. Attempting to proceed."
            self.logger.warning(msg, hypervisor)

    def post_create(self, **params):
        self.get_attr_from_res()
        
    def pre_create(self, **params):
        """Check input params before resource creation. Use this to format parameters for service creation
        Extend this function to manipulate and validate create input params.

        :param params: input params
        :return: resource input params
        :raise ApiManagerError:
        """
        account_id = self.instance.account_id

        # base quotas
        quotas = {
            "lbaas.cores": 0,
            "lbaas.instances": 1,
            "lbaas.ram": 0,
        }

        # get container
        container_id = self.get_config("container")  # dalla definition di flavor
        flavor_resource_uuid = self.get_config("flavor")  # dalla definition di flavor
        compute_zone = self.get_config("computeZone")
        # data_instance = self.get_config("dbinstance")
        engine_config = self.get_config("engine_config")  # dalla definition di template
        hypervisor = engine_config.get("hypervisor")
        if engine_config is None:
            engine_config = {}
        image_engine = engine_config.get("image")

        # get resource image
        image_resource: dict = self.get_image(image_engine)
        image_configs = image_resource.get("attributes", {}).get("configs", {})
        # image_volume_size = image_configs.get("min_disk_size")
        image_ram_size_gb = image_configs.get("min_ram_size", 0)
        self.logger.debug("+++++ image_ram_size_gb: %s", image_ram_size_gb)

        # get Flavor resource Info
        flavor_resource: dict = self.get_flavor(flavor_resource_uuid)

        # try to get main volume size from flavor
        flavor_configs = flavor_resource.get("attributes", None).get("configs", None)
        quotas["lbaas.cores"] = flavor_configs.get("vcpus", 0)
        quotas["lbaas.ram"] = flavor_configs.get("memory", 0)
        if quotas["lbaas.ram"] > 0:
            quotas["lbaas.ram"] = quotas["lbaas.ram"] / 1024
        root_disk_size = flavor_configs.get("disk", 40)

        flavor_memory = flavor_configs.get("memory", 0)
        self.logger.debug("+++++ flavor_memory: %s", flavor_memory)
        image_ram_size_mb = image_ram_size_gb * 1024
        if flavor_memory < image_ram_size_mb:
            raise ApiManagerError(
                "Minimum memory required is %s GB - flavor memory: %s MB" % (image_ram_size_gb, flavor_memory)
            )

        # get availability zone from request parameters #
        # we use site as AZ becouse of "AZ" meaninig in Nivola2
        av_zone = engine_config.get("site", None)
        subnet_resource = engine_config.get("subnet", None)
        vpc_resource_uuid: Optional[str] = None  # = engine_config.get("vpc_name", None)
        subnet_cidr: Optional[str] = None

        # check if subnet is a service
        subnet_id: Optional[str] = self.get_config("subnet")
        if subnet_id is not None:
            # user gave service subnet
            subnet_inst = self.controller.check_service_instance(subnet_id, ApiComputeSubnet, account=account_id)
            # subnet_inst = self.controller.check_service_instance(subnet_id, ApiComputeSubnet, account=account_id)
            # subnet_name = subnet_inst.name
            # subnet_resource = subnet_inst.resource_uuid
            subnet_inst.get_main_config()
            av_zone = subnet_inst.get_config("site")
            subnet_cidr = subnet_inst.get_config("cidr")
            vpc_resource_uuid = self.controller.get_service_instance(
                subnet_inst.model.linkParent[0].start_service_id
            ).resource_uuid

        else:
            # get subnet from template
            subnet_resource = engine_config.get("subnet", None)
            vpc_resource_uuid = engine_config.get("vpc_name", None)
            if subnet_resource is None:
                raise ApiManagerError("You need to specify a subnet")
            res_network: dict = self.controller.api_client.admin_request(
                "resource", f"v2.0/nrs/provider/site_networks/{subnet_resource}", "get"
            ).get("site_network", {})
            subnet_cidr = res_network.get("attributes", {}).get("configs", {}).get("subnets", [{}])[0].get("cidr", None)
            if av_zone is None:
                site_id = res_network.get("parent")
                av_zone = (
                    self.controller.api_client.admin_request("resource", f"v1.0/nrs/entities/{site_id}", "get")
                    .get("resource", {})
                    .get("name")
                )
            # vpcs: List[dict] = self.controller.api_client.admin_request(
            #     subsystem="resource",
            #     path=f"v1.0/nrs/entities/{subnet_id}/linked",
            #     method="get",
            #     data={"type": "Provider.ComputeZone.Vpc"},
            # ).get("resources", [])
            # if len(vpcs) > 0:
            #     vpc_resource_uuid = vpcs[0].get("uuid")

        # subnet_id = engine_config.get("subnet", None)
        if subnet_cidr is None:
            raise ApiManagerError("Subnet cidr is not defined")

        if av_zone is None:
            raise ApiManagerError("Site or AZ is not defined")

        # check availability zone status
        if self.is_availability_zone_active(compute_zone, av_zone) is False:
            raise ApiManagerError("Availability zone %s is not in available status" % av_zone)

        # get and check the id SecurityGroupId
        sg: str = self.get_config("security_group_id")
        sg_inst = self.controller.check_service_instance(sg, ApiComputeSecurityGroup, account=account_id)
        if sg_inst.resource_uuid is None:
            raise ApiManagerError("SecurityGroup id %s is invalid" % sg)
        sg_resource_uuid = sg_inst.resource_uuid

        # link security group to db instance
        self.instance.add_link(
            name="link-%s-%s" % (self.instance.oid, sg_inst.oid),
            type="sg",
            end_service=sg_inst.oid,
            attributes={},
        )
        if sg_resource_uuid is None:
            raise ApiManagerError("SecurityGroup is not correct")

        # Check vpc subnet ip avalability
        if vpc_resource_uuid is not None:
            self.check_available_ip(vpc_resource_uuid=vpc_resource_uuid, az=av_zone, hypervisor=hypervisor)

        # get params for given engine and version
        host_group = engine_config.get("host_group")
        volume_flavor = engine_config.get("volume_flavor")
        image = engine_config.get("image")

        # bypass key for pgsql engine
        key_name = engine_config.get("key_name")

        # name = '%s-%s' % (self.instance.name, id_gen(length=8))
        name = self.instance.name
        hostname = name

        engine_configs = deepcopy(engine_config.get("engine_params"))
        engine_configs["haproxy_config"] = self.get_haproxy_config()
        data: CreatePaasParamRequestDict = {
            # desc: str
            "desc": name,
            # orchestrator_tag: str
            "orchestrator_tag": "default",
            # name: str
            "name": name,
            # container: str
            "container": container_id,
            # tags: str
            # compute_zone: str
            "compute_zone": compute_zone,
            # availability_zone: str
            "availability_zone": av_zone,
            # multi_avz :bool
            "multi_avz": False,
            # flavor :str
            "flavor": flavor_resource_uuid,
            # volume_flavor :str
            "volume_flavor": volume_flavor,
            # image :str
            "image": image,
            # vpc :str
            "vpc": vpc_resource_uuid,
            # subnet :str
            "subnet": subnet_cidr,
            # security_group :str
            "security_group": sg_resource_uuid,
            # engine_admin_user :str
            "engine_admin_user": name,
            # engine_admin_password :str
            "engine_admin_password": self.user_pasword,
            # key_name :str
            "key_name": key_name,
            # version :str
            "version": "0",
            # engine :str
            "engine": "lbaas",
            # engine_configs : dict
            "engine_configs": engine_configs,
            # root_disk_size :int
            "root_disk_size": root_disk_size,
            # resolve :bool
            "resolve": True,
            # hostname :str
            "hostname": hostname,
            # host_group :str
            "host_group": host_group,
            # hypervisor :str
            "hypervisor": hypervisor,
            # csi_custom: bool
            "csi_custom": False,
            # enable_monitor: bool
            "enable_monitor": True,
        }

        params["resource_params"] = data
        from beecell.debug import dbg

        dbg(data, params)

        # import pprint
        # from io import StringIO
        # msg = StringIO("Pre create params: ")
        # pprint.pp(params, stream=msg)
        # self.logger.debug(msg)
        # self.logger.debug("Pre create params: %s" % obscure_data(deepcopy(params)))

        return params

    @trace(op="insert")
    def create_resource(self, task, *args, **kvargs):
        """Create resource
        Warning!
        This method call a wait_for_task and must be run only by an asyncronus worker!

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        data = {"paas": args[0]}
        # from beecell.debug import dbg
        # dbg(data)
        ## add engine configuration from definition as resurce parameter

        self.logger.debug("+++++++++++++ %s ", json.dumps(data, indent=4))
        try:
            uri = "/v1.0/nrs/provider/paas"
            res = self.controller.api_client.admin_request("resource", uri, "post", data=data)
            uuid = res.get("uuid", None)
            taskid = res.get("taskid", None)
            self.logger.debug("Create sql stack resource: %s" % uuid)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=1)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        # set resource uuid
        if uuid is not None and taskid is not None:
            self.set_resource(uuid)
            self.update_status(SrvStatusType.PENDING)
            # FF: maxtime=1200 -> maxtime=3600
            self.wait_for_task(taskid, delta=2, maxtime=3600, task=task)
            self.update_status(SrvStatusType.CREATED)
            self.controller.logger.debug("Update lbaas resource: %s" % uuid)
        return uuid

    # def pre_import(self, **params):
    #     """Check input params before resource import. Use this to format parameters for service creation
    #     Extend this function to manipulate and validate create input params.

    #     return params

    # def post_import(self, **params):
    #     """Post import function. Use this after service creation.
    #     Extend this function to execute some operation after entity was created.

    #     :param params: input params
    #     :return: None
    #     :raise ApiManagerError:
    #     """
    #     return None

    # def pre_update(self, **params):
    #     """Pre update function. This function is used in update method.

    #     :param params: input key=value params
    #     :return: params
    #     :raises ApiManagerError: raise :class:`.ApiManagerError`
    #     """
    #     pass

    def applyconfiguration(self):
        if self.get_status() not in ["ACTIVE", "ERROR"]:
            raise ApiManagerError("Instance %s is not in a correct state" % self.instance.uuid)
        hacfg = self.get_haproxy_config()
        params = {
            "resource_params": {
                "action": "apply",
                "engine_configs": {
                    "haproxy_config": hacfg,
                },
            }
        }
        res = self.update(**params)
        return res

    def update_resource(self, task, *args, **kvargs):
        """Update resource

        :param task: celery task which is calling the method
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        ### TODO TEMPORARY DBG
        import pprint

        print(f"lbaas {self.instance.uuid} update rsource")
        pprint.pp(kvargs)
        try:
            if len(kvargs.keys()) > 0:
                data = {"paas": kvargs}
                # from beecell.debug import dbg
                # dbg(data)
                uri = "/v1.0/nrs/provider/paas/%s" % self.instance.resource_uuid
                res = self.controller.api_client.admin_request("resource", uri, "put", data=data)
                taskid = res.get("taskid", None)
                if taskid is not None:
                    self.wait_for_task(taskid, delta=4, maxtime=600, task=task)
                self.logger.debug("Update load balancer resources: %s" % res)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.instance.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        return True

    def delete_resource(self, task, *args, **kvargs):
        """Delete resource

        Warning!
        This method call a wait_for_task and must be run only by an asyncronus worker!

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        ## TODO review

        # call superclass method
        if self.check_resource() is None:
            return False

        try:
            uuid = self.instance.resource_uuid
            if uuid is not None:
                uri = "/v1.0/nrs/provider/paas/%s" % uuid
            else:
                return False
            res = self.controller.api_client.admin_request("resource", uri, "delete", data="")
            taskid = res.get("taskid", None)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=1)
            self.instance.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=1)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        if taskid is not None:
            self.wait_for_task(taskid, delta=4, maxtime=600, task=task)
        self.logger.debug("Delete sql stack resources: %s" % res)

        return True

    def action_resource(self, task, *args, **kvargs):
        """Send action to resource

        :param task: celery task reference
        :param args: custom positional args
        :param kvargs: custom key=value args
        :return: True
        :raises ApiManagerError: raise :class:`.ApiManagerError`
        """
        action = kvargs.pop("action", None)
        params = kvargs.pop("args", None)
        uuid = self.instance.resource_uuid
        try:
            data = {"action": {action: params}}
            uri = "/v1.0/nrs/provider/loadbalancers/%s/action" % uuid
            res = self.controller.api_client.admin_request("resource", uri, "put", data=data)
            taskid = res.get("taskid", None)
        except ApiManagerError as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=ex.value)
            raise
        except Exception as ex:
            self.logger.error(ex, exc_info=True)
            self.update_status(SrvStatusType.ERROR, error=str(ex))
            raise ApiManagerError(str(ex))

        # set resource uuid
        if taskid is not None:
            self.wait_for_task(taskid, delta=2, maxtime=600, task=task)
        self.logger.debug("Send action '%s' to load balancer resources: %s" % (action, res))

        return True
