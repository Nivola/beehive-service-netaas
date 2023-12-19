# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2020-2022 Regione Piemonte
# (C) Copyright 2018-2023 CSI-Piemonte

from flasgger import Schema
from six import ensure_text
from beehive_service.views import ServiceApiView, NotEmptyString
from beecell.swagger import SwaggerHelper
from flasgger.marshmallow_apispec import fields
from marshmallow.validate import OneOf, Regexp, Length
from marshmallow.decorators import validates_schema, validates
from marshmallow.exceptions import ValidationError
from beehive_service.plugins.computeservice.controller import (
    ApiComputeVPC,
    ApiComputeSecurityGroup,
    ApiComputeService,
)
from beehive.common.apimanager import SwaggerApiView, ApiView
from beecell.types.type_string import is_blank
from ipaddress import IPv4Address, IPv6Network, AddressValueError
from beehive_service.service_util import (
    __REGEX_AWS_SG_NAME_AND_DESC__,
    __RULE_GROUP_INGRESS__,
    __RULE_GROUP_EGRESS__,
)
from beehive.common.data import operation


class InstanceTagSetResponseSchema(Schema):
    key = fields.String(required=False, allow_none=True, description="tag key")
    value = fields.String(required=False, allow_none=True, description="tag value")


class PrefixListIdSchema(Schema):
    prefixListId = fields.String(example="", required=False, allow_none=True, description="ID of the prefix")
    description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="Description of security group for  the prefix id",
    )


class IpRangeResponseSchema(Schema):
    cidrIp = fields.String(example="", required=False, allow_none=True, description="IPv4 CIDR")
    description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="Description of IPv4 CIDR",
    )


class IpRangeRequestSchema(Schema):
    CidrIp = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IPv4 CIDR (supported format:xxx.xxx.xxx.xxx/xx)",
        context="query",
    )
    Description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="Description of IPv4 CIDR",
        context="query",
    )

    @validates("CidrIp")
    def validate_cidr_ipv4(self, cidr_ip, *args, **kvargs):
        if cidr_ip is None or is_blank(cidr_ip):
            return
        ip, prefix = cidr_ip.split("/")
        try:
            IPv4Address(ensure_text(ip))
            prefix = int(prefix)
        except AddressValueError:
            if prefix <= 0 or prefix > 32:
                raise ValidationError("parameter is malformed. Range network prefix must be >= 0 and < 33")
            raise ValidationError("parameter is malformed. Use xxx.xxx.xxx.xxx/xx syntax")


class Ipv6RangeResponseSchema(Schema):
    cidrIpv6 = fields.String(example="", required=False, allow_none=True, description="IPv6 CIDR")
    description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="Description of IPv6 CIDR",
    )

    @validates("cidrIpv6")
    def validate_cidr_ipv6(self, cidr_ipv6):
        if cidr_ipv6 is None or is_blank(cidr_ipv6):
            return

        ip, prefix = cidr_ipv6.split("::")
        try:
            IPv6Network(ensure_text(ip))
        except Exception:
            raise ValidationError("{input} is malformed. Use xxxx:xxxx:xxxx:xxxx::xx syntax")


class Ipv6RangeRequestSchema(Schema):
    CidrIpv6 = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IPv6 CIDR",
        context="query",
    )
    Description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="Description of IPv6 CIDR",
        context="query",
    )


class UserIdGroupPairResponseSchema(Schema):
    description = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="description for the security group rule",
    )
    groupName = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="name of the security group",
    )
    groupId = fields.String(example="", required=False, allow_none=True, description="security group id")
    peeringStatus = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="status of a VPC peering connection",
    )
    userId = fields.String(example="", required=False, allow_none=True, description="account id")
    nvl_userName = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="account name or id",
        data_key="nvl-userName",
    )
    vpcId = fields.String(example="", required=False, allow_none=True, description="vpc id")
    vpcPeeringConnectionId = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="id of the VPC peering connection",
    )


class UserIdGroupPairRequestSchema(Schema):
    # Description = fields.String(example='', required=False, allow_none=True,
    #                             description='security group rule description', context='query',
    #                             validate=Regexp(__REGEX_AWS_SG_NAME_AND_DESC__))
    # GroupId = fields.String(example='', required=False, allow_none=True,
    #                         description='security group rule name', context='query')
    GroupName = fields.String(
        example="",
        required=False,
        description="security group rule name",
        context="query",
        validate=Regexp(__REGEX_AWS_SG_NAME_AND_DESC__),
    )
    # PeeringStatus = fields.String(example='', required=False, allow_none=True,
    #                               description='status of a VPC peering connection', context='query')
    # UserId = fields.String(example='', required=False, allow_none=True, description='account id', context='query')
    # VpcId = fields.String(example='', required=False, allow_none=True, description='vpc id', context='query')
    # VpcPeeringConnectionId = fields.String(example='', required=False, allow_none=True,
    #                                        description='id of the VPC peering connection', context='query')


class IpPermissionsParameterResponseSchema(Schema):
    fromPort = fields.Integer(
        example="",
        required=False,
        allow_none=True,
        description="start of port range for the protocols",
    )
    toPort = fields.Integer(
        example="",
        required=False,
        allow_none=True,
        description="end of port range for the protocols",
    )
    ipProtocol = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IP protocol for a security group rule",
    )
    prefixListIds = fields.Nested(
        PrefixListIdSchema,
        many=True,
        required=False,
        allow_none=True,
        description="one or more prefix list IDs for a service",
    )
    ipRanges = fields.Nested(
        IpRangeResponseSchema,
        many=True,
        required=False,
        allow_none=True,
        description="one or more ipv4 range",
    )
    ipv6Ranges = fields.Nested(
        Ipv6RangeResponseSchema,
        many=True,
        required=False,
        allow_none=True,
        description="one or more ipv6 range",
    )
    groups = fields.Nested(
        UserIdGroupPairResponseSchema,
        many=True,
        required=False,
        allow_none=True,
        description="ine or more security group and account ID pairs",
    )
    nvl_state = fields.String(
        required=False,
        allow_none=True,
        description="state of security group rule",
        data_key="nvl-state",
    )
    nvl_reserved = fields.Boolean(
        required=False,
        allow_none=True,
        description="check if rule for security group is reserved",
        data_key="nvl-reserved",
    )


class IpPermissionsParameterRequestSchema(Schema):
    FromPort = fields.Integer(
        required=False,
        missing=-1,
        example="",
        context="query",
        description="start of port range for the protocols tcp, udp. Subprotocol for icmp",
    )
    ToPort = fields.Integer(
        required=False,
        missing=-1,
        example="",
        context="query",
        description="end of port range for the protocols",
    )
    IpProtocol = fields.String(
        required=False,
        validate=OneOf(["tcp", "udp", "icmp", "-1"]),
        description="IP protocol for security group rule",
        context="query",
    )
    prefixListIds = fields.Nested(
        PrefixListIdSchema,
        many=True,
        required=False,
        description="One or more prefix list IDs for a service",
        context="query",
    )
    IpRanges = fields.Nested(
        IpRangeRequestSchema,
        many=True,
        required=False,
        description="one or more ipv4 range",
        validation=(lambda n: 0 <= n <= 6553 or n == -1),
        context="query",
    )
    Ipv6Ranges = fields.Nested(
        Ipv6RangeRequestSchema,
        many=True,
        required=False,
        context="query",
        description="one or more ipv6 range",
    )
    UserIdGroupPairs = fields.Nested(
        UserIdGroupPairRequestSchema,
        many=True,
        required=False,
        context="query",
        description="One or more security group and account ID pairs",
    )


class IpPermissionsSGParameterResponseSchema(Schema):
    ip_permission_cidr_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IPv4 CIDR block for an inbound security group rule",
    )
    ip_permission_from_port_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="For an inbound rule, the start of port range for the TCP "
        "and UDP protocols, or an ICMP type number",
    )
    ip_permission_group_id_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="ID of a security group that has been referenced in an " "inbound security group rule",
    )
    ip_permission_group_name_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="ID of a security group that has been referenced in an " "inbound security group rule",
    )
    ip_permission_ipv6_cidr_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IPv6 CIDR block for an inbound security group rule",
    )
    ip_permission_prefix_list_id_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="The ID (prefix) of the service to which a security " "group rule allows inbound access",
    )
    ip_permission_protocol_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="IP protocol for an inbound security group rule",
    )
    ip_permission_to_port_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="port range for the protocols",
    )
    ip_permission_user_id_N = fields.String(
        example="",
        required=False,
        allow_none=True,
        description="ID of an  account that has been referenced in an inbound " "security group rule",
    )


class SecurityGroupStateReasonResponseSchema(Schema):
    nvl_code = fields.Integer(
        required=False,
        allow_none=True,
        example="400",
        description="state code",
        data_key="nvl-code",
    )
    nvl_message = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="state message",
        data_key="nvl-message",
    )


class SecurityGroupItemParameterResponseSchema(Schema):
    groupDescription = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="instance security group description",
    )
    groupId = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="instance security group identifier",
    )
    groupName = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="instance security group name",
    )
    ipPermissions = fields.Nested(
        IpPermissionsParameterResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        description="One or more inbound rules associated with the security group",
    )
    ipPermissionsEgress = fields.Nested(
        IpPermissionsParameterResponseSchema,
        required=False,
        many=True,
        allow_none=True,
        description="One or more outbound rules associated with the security group",
    )
    ownerId = fields.String(
        required=False,
        allow_none=True,
        example="",
        description="account ID of the owner of the instance security group",
    )
    tagSet = fields.Nested(InstanceTagSetResponseSchema, many=True, required=False, allow_none=True)
    vpcId = fields.String(required=False, allow_none=True, example="", descriptiom="ID of VPC")
    nvl_vpcName = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="Name of the VPC",
        data_key="nvl-vpcName",
    )
    nvl_sgOwnerId = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="ID of the account that owns the security group",
        data_key="nvl-sgOwnerId",
    )
    nvl_sgOwnerAlias = fields.String(
        required=False,
        allow_none=True,
        example="",
        descriptiom="Alias name of the account that owns the security group",
        data_key="nvl-sgOwnerAlias",
    )

    nvl_state = fields.String(
        required=False,
        example="",
        description="state of the SecurityGroup",
        data_key="nvl-state",
        validate=OneOf(
            [
                getattr(ApiComputeSecurityGroup.state_enum, x)
                for x in dir(ApiComputeSecurityGroup.state_enum)
                if not x.startswith("__")
            ]
        ),
    )
    # ['pending', 'available', 'deregistering', 'deregistered', 'transient', 'error', 'updating', 'unknown']
    nvl_stateReason = fields.Nested(
        SecurityGroupStateReasonResponseSchema,
        many=False,
        required=False,
        allow_none=True,
        data_key="nvl-stateReason",
    )


class DescribeSecurityGroups1ResponseSchema(Schema):
    nextToken = fields.String(required=True, allow_none=True)
    requestId = fields.String(required=True, allow_none=True)
    securityGroupInfo = fields.Nested(
        SecurityGroupItemParameterResponseSchema,
        many=True,
        required=False,
        allow_none=True,
    )
    nvl_securityGroupTotal = fields.Integer(
        required=False,
        example="0",
        descriptiom="total security group",
        data_key="nvl-securityGroupTotal",
    )
    xmlns = fields.String(required=False, data_key="$xmlns")


class DescribeSecurityGroupsResponseSchema(Schema):
    DescribeSecurityGroupsResponse = fields.Nested(
        DescribeSecurityGroups1ResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class DescribeSecurityGroupsRequestSchema(Schema):
    owner_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="owner-id.N",
        description="account ID  of the security_group owner",
    )
    # description_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                             context='query', collection_format='multi', data_key='description.N',
    #                             description='security group description')
    # egress_ip_permission_cidr_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                           context='query', collection_format='multi',
    #                                           data_key='egress.ip-permission.cidr.N',
    #                                           description='IPv4 CIDR block for an outbound security group rule')
    # egress_ip_permission_from_port_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                context='query', collection_format='multi',
    #                                                data_key='egress.ip-permission.from-port.N',
    #                                                description='For an outbound rule, the start of port range for the '
    #                                                            'TCP and UDP protocols, or an ICMP type number')
    # egress_ip_permission_group_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                               context='query', collection_format='multi',
    #                                               data_key='egress.ip-permission.group-id.N',
    #                                               description='ID of a security group that has been referenced in an '
    #                                                           'outbound security group rule')
    # egress_ip_permission_group_name_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                 context='query', collection_format='multi',
    #                                                 data_key='egress.ip-permission.group-name.N',
    #                                                 description='ID of a security group that has been referenced in '
    #                                                             'an outbound security group rule')
    # egress_ip_permission_ipv6_cidr_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                context='query', collection_format='multi',
    #                                                data_key='egress.ip-permission.ipv6-cidr.N',
    #                                                description='IPv6 CIDR block for an outbound security group rule')
    # egress_ip_permission_prefix_list_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                                     context='query', collection_format='multi',
    #                                                     data_key='egress.ip-permission.prefix-list-id.N',
    #                                                     description='The ID (prefix) of the service to which a '
    #                                                                 'security group rule allows outbound access')
    # egress_ip_permission_protocol_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                               context='query', collection_format='multi',
    #                                               data_key='egress.ip-permission.protocol.N',
    #                                               description='IP protocol for an outbound security group rule')
    # egress_ip_permission_to_port_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                              context='query', collection_format='multi',
    #                                              data_key='egress.ip-permission.to-port.N',
    #                                              description='port range for the protocols')
    # egress_ip_permission_user_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                              context='query', collection_format='multi',
    #                                              data_key='egress.ip-permission.user-id.N',
    #                                              description='ID of an  account that has been referenced in an '
    #                                                          'outbound security group rule')
    group_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="group-id.N",
        description="ID of the security group",
    )
    group_name_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="group-name.N",
        description="Name of the security group",
    )
    # ip_permission_cidr_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                    context='query', collection_format='multi', data_key='ip-permission.cidr.N',
    #                                    description='IPv4 CIDR block for an inbound security group rule')
    # ip_permission_from_port_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                         context='query', collection_format='multi',
    #                                         data_key='ip-permission.from-port.N',
    #                                         description='For an inbound rule, the start of port range for the TCP '
    #                                                     'and UDP protocols, or an ICMP type number')
    # ip_permission_group_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                        context='query', collection_format='multi',
    #                                        data_key='ip-permission.group-id.N',
    #                                        description='ID of a security group that has been referenced in an '
    #                                                    'inbound security group rule')
    # ip_permission_group_name_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                          context='query', collection_format='multi',
    #                                          data_key='ip-permission.group-name.N',
    #                                          description='ID of a security group that has been referenced in an '
    #                                                      'inbound security group rule')
    # ip_permission_ipv6_cidr_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                         context='query', collection_format='multi',
    #                                         data_key='ip-permission.ipv6-cidr.N',
    #                                         description='IPv6 CIDR block for an inbound security group rule')
    # ip_permission_prefix_list_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                              context='query', collection_format='multi',
    #                                              data_key='ip-permission.prefix-list-id.N',
    #                                              description='The ID (prefix) of the service to which a security '
    #                                                          'group rule allows inbound access')
    # ip_permission_protocol_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                        context='query', collection_format='multi',
    #                                        data_key='ip-permission.protocol.N',
    #                                        description='IP protocol for an inbound security group rule')
    # ip_permission_to_port_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                       context='query', collection_format='multi',
    #                                       data_key='ip-permission.to-port.N',
    #                                       description='port range for the protocols')
    # ip_permission_user_id_N = fields.List(fields.String(example=''), required=False, allow_none=True,
    #                                       context='query', collection_format='multi',
    #                                       data_key='ip-permission.user-id.N',
    #                                       description='ID of an  account that has been referenced in an inbound '
    #                                                   'security group rule')
    tag_key_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=True,
        context="query",
        collection_format="multi",
        data_key="tag-key.N",
        descriptiom="value of a tag assigned to the resource",
    )
    vpc_id_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="vpc-id.N",
        description="One or more VPC IDs",
    )
    GroupId_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="GroupId.N",
        description="One or more security group IDs",
    )
    GroupName_N = fields.List(
        fields.String(example=""),
        required=False,
        allow_none=False,
        context="query",
        collection_format="multi",
        data_key="GroupName.N",
        description="One or more security group names",
    )
    MaxResults = fields.Integer(required=False, default=0, description="", context="query")
    NextToken = fields.String(required=False, default="1", description="", context="query")


class DescribeSecurityGroups(ServiceApiView):
    summary = "Describe compute security group"
    description = "Describe compute security group"
    tags = ["computeservice"]
    definitions = {"DescribeSecurityGroupsResponseSchema": DescribeSecurityGroupsResponseSchema}
    parameters = SwaggerHelper().get_parameters(DescribeSecurityGroupsRequestSchema)
    parameters_schema = DescribeSecurityGroupsRequestSchema
    responses = ServiceApiView.setResponses(
        {
            200: {
                "description": "success",
                "schema": DescribeSecurityGroupsResponseSchema,
            }
        }
    )
    response_schema = DescribeSecurityGroupsResponseSchema

    def get(self, controller, data, *args, **kwargs):
        data_search = {}
        data_search["size"] = data.get("MaxResults", 10)
        data_search["page"] = int(data.get("NextToken", 0))

        # check Account
        account_id_list = data.get("owner_id_N", [])
        account_id_list.extend(data.get("requester_id_N", []))
        if data.get("owner_id", None) is not None:
            account_id_list.extend([data.get("owner_id", None)])

        # get instance identifier
        instance_id_list = data.get("group_id_N", [])
        instance_id_list.extend(data.get("GroupId_N", []))
        instance_id_list.extend(data.get("group_name_N", []))
        instance_id_list.extend(data.get("GroupName_N", []))

        # get vpc
        vpc_ids = data.get("vpc_id_N", [])
        for vpc_id in vpc_ids:
            vpc_srv = controller.get_service_type_plugin(vpc_id, plugin_class=ApiComputeVPC)
            vpc_sg_srvs = vpc_srv.get_child_type_plugin_instances(plugin_class=ApiComputeSecurityGroup)
            for sg in vpc_sg_srvs:
                if sg.instance.uuid not in instance_id_list:
                    instance_id_list.append(sg.instance.uuid)

        # get tags
        tag_values = data.get("tag_key_N", None)

        # get instances list
        res, total = controller.get_service_type_plugins(
            service_uuid_list=instance_id_list,
            account_id_list=account_id_list,
            servicetags_or=tag_values,
            plugintype=ApiComputeSecurityGroup.plugintype,
            **data_search,
        )

        # format result
        instances_set = [r.aws_info() for r in res]

        res = {
            "DescribeSecurityGroupsResponse": {
                "$xmlns": self.xmlns,
                "requestId": operation.id,
                "nextToken": str(data_search["page"] + 1),
                "securityGroupInfo": instances_set,
                "nvl-securityGroupTotal": total,
            }
        }
        return res


class CreateSecurityGroupApiResponse1Schema(Schema):
    groupId = fields.String(required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class CreateSecurityGroupApiResponseSchema(Schema):
    CreateSecurityGroupResponse = fields.Nested(CreateSecurityGroupApiResponse1Schema, required=True, allow_none=False)


class CreateSecurityGroupParamApiRequestSchema(Schema):
    # owner_id = fields.String(required=True, example='', description='account id')
    GroupDescription = fields.String(
        required=False,
        default="",
        example="",
        description="a description for the security group",
    )
    GroupName = fields.String(required=True, example="", description="name of the security group")
    VpcId = fields.String(
        required=True,
        example="",
        description="ID of the VPC",
        validate=Length(1, error="VpcId Must not be Empty"),
    )
    GroupType = NotEmptyString(required=False, description="security group template", allow_none=True)


class CreateSecurityGroupApiRequestSchema(Schema):
    security_group = fields.Nested(CreateSecurityGroupParamApiRequestSchema, context="body")


class CreateSecurityGroupApiBodyRequestSchema(Schema):
    body = fields.Nested(CreateSecurityGroupApiRequestSchema, context="body")


class CreateSecurityGroup(ServiceApiView):
    summary = "Create compute security group"
    description = "Create compute security group"
    tags = ["computeservice"]
    definitions = {
        "CreateSecurityGroupApiRequestSchema": CreateSecurityGroupApiRequestSchema,
        "CreateSecurityGroupApiResponseSchema": CreateSecurityGroupApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(CreateSecurityGroupApiBodyRequestSchema)
    parameters_schema = CreateSecurityGroupApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            202: {
                "description": "success",
                "schema": CreateSecurityGroupApiResponseSchema,
            }
        }
    )
    response_schema = CreateSecurityGroupApiResponseSchema

    def post(self, controller, data, *args, **kwargs):
        inner_data = data.get("security_group")
        sg_name = inner_data.get("GroupName")
        sg_desc = inner_data.get("GroupDescription", sg_name)
        sg_type = inner_data.get("GroupType", None)
        vpc_id = inner_data.get("VpcId")

        # check instance with the same name already exists
        # self.service_exist(controller, sg_name, ApiComputeSecurityGroup.plugintype)

        # get vpc service
        inst_vpc = controller.get_service_type_plugin(vpc_id, plugin_class=ApiComputeVPC, details=False)
        account_id = inst_vpc.instance.account_id

        # check account
        account, parent_plugin = self.check_parent_service(
            controller, account_id, plugintype=ApiComputeService.plugintype
        )

        # get security group template
        if sg_type is not None:
            service_definition = controller.get_service_def(sg_type)
        else:
            service_definition = controller.get_default_service_def(ApiComputeSecurityGroup.plugintype)

        data["computeZone"] = parent_plugin.resource_uuid
        inst = controller.add_service_type_plugin(
            service_definition.oid,
            account_id,
            name=sg_name,
            desc=sg_desc,
            parent_plugin=inst_vpc,
            instance_config=data,
        )

        res = {
            "CreateSecurityGroupResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "groupId": inst.instance.uuid,
            }
        }
        self.logger.debug("Service Aws response: %s" % res)

        return res, 202


class PatchSecurityGroupApiResponse1Schema(Schema):
    groupId = fields.String(required=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)


class PatchSecurityGroupApiResponseSchema(Schema):
    PatchSecurityGroupResponse = fields.Nested(PatchSecurityGroupApiResponse1Schema, required=True, allow_none=False)


class PatchSecurityGroupParamApiRequestSchema(Schema):
    GroupName = fields.String(required=True, example="", description="uuid of the security group")
    # GroupType = fields.String(required=False, missing=None, description='security group template', allow_none=True)


class PatchSecurityGroupApiRequestSchema(Schema):
    security_group = fields.Nested(PatchSecurityGroupParamApiRequestSchema, context="body")


class PatchSecurityGroupApiBodyRequestSchema(Schema):
    body = fields.Nested(PatchSecurityGroupApiRequestSchema, context="body")


class PatchSecurityGroup(ServiceApiView):
    summary = "Patch compute security group"
    description = "Patch compute security group"
    tags = ["computeservice"]
    definitions = {
        "PatchSecurityGroupApiRequestSchema": PatchSecurityGroupApiRequestSchema,
        "PatchSecurityGroupApiResponseSchema": PatchSecurityGroupApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(PatchSecurityGroupApiBodyRequestSchema)
    parameters_schema = PatchSecurityGroupApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {202: {"description": "success", "schema": PatchSecurityGroupApiResponseSchema}}
    )
    response_schema = PatchSecurityGroupApiResponseSchema

    def patch(self, controller, data, *args, **kwargs):
        data = data.get("security_group")
        sg_uuid = data.get("GroupName")

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        type_plugin.patch(**data)

        instances_set = [
            {
                "groupId": type_plugin.instance.uuid,
            }
        ]
        res = self.format_create_response("PatchSecurityGroupResponse", instances_set)

        return res, 202


class DeleteSecurityGroupApiResponse1Schema(Schema):
    return_ = fields.Boolean(required=True, allow_none=False, data_key="return")
    requestId = fields.String(required=True, allow_none=True)


class DeleteSecurityGroupApiResponseSchema(Schema):
    DeleteSecurityGroupResponse = fields.Nested(DeleteSecurityGroupApiResponse1Schema, required=True, allow_none=False)


class DeleteSecurityGroupParamApiRequestSchema(Schema):
    GroupName = fields.String(required=True, example="", description="uuid of the security group")


class DeleteSecurityGroupApiRequestSchema(Schema):
    security_group = fields.Nested(DeleteSecurityGroupParamApiRequestSchema, context="body")


class DeleteSecurityGroupApiBodyRequestSchema(Schema):
    body = fields.Nested(DeleteSecurityGroupApiRequestSchema, context="body")


class DeleteSecurityGroup(ServiceApiView):
    summary = "Delete compute security group"
    description = "Delete compute security group"
    tags = ["computeservice"]
    definitions = {
        "DeleteSecurityGroupApiRequestSchema": DeleteSecurityGroupApiRequestSchema,
        "DeleteSecurityGroupApiResponseSchema": DeleteSecurityGroupApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(DeleteSecurityGroupApiBodyRequestSchema)
    parameters_schema = DeleteSecurityGroupApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            202: {
                "description": "success",
                "schema": DeleteSecurityGroupApiResponseSchema,
            }
        }
    )
    response_schema = DeleteSecurityGroupApiResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        data = data.get("security_group")
        sg_uuid = data.get("GroupName")

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        type_plugin.delete()

        res = {
            "DeleteSecurityGroupResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "return": True,
            }
        }

        return res, 202


class AuthorizeSGroupEgressApi1ResponseSchema(Schema):
    # Return is return in aws
    Return = fields.Boolean(required=True, example=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)
    nvl_activeTask = fields.String(
        required=True,
        allow_none=True,
        data_key="nvl-activeTask",
        description="active task id",
    )


class AuthorizeSGroupEgressApiResponseSchema(Schema):
    AuthorizeSecurityGroupEgressResponse = fields.Nested(
        AuthorizeSGroupEgressApi1ResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class AuthorizeSGroupEgressParamsApiRequestSchema(Schema):
    # GroupId = fields.String(required=True, example='', description='id of the security group')
    GroupName = fields.String(
        required=False,
        example="",
        description="name of the security group",
        context="query",
    )
    IpPermissions_N = fields.List(
        fields.Nested(IpPermissionsParameterRequestSchema),
        required=False,
        context="query",
        collection_format="multi",
        data_key="IpPermissions.N",
        description="sets of ip permission",
    )

    # deprecated
    # IpProtocol = fields.String(required=False, allow_none=True,
    #                            validate=OneOf(['tcp', 'udp', 'icmp', '-1']),
    #                            description='IP protocol for security group rule', context='query', )
    # FromPort = fields.Integer(required=False, allow_none=True, example='',
    #                           description='start of port range for the protocols (TPC)', context='query')
    # ToPort = fields.Integer(required=False, allow_none=True, example='',
    #                         description='end of port range for the protocols', context='query')
    # GroupName = fields.String(required=False, example='', description='name of the security group', context='query')
    # SourceSecurityGroupName = fields.String(required=False, allow_none=True, example='',
    #                                         description='name of the source security group', context='query')
    # SourceSecurityGroupOwnerId = fields.String(required=False, allow_none=True, example='',
    #                                            description='owner ID of the source security group', context='query')
    # CidrIp = fields.String(required=False, allow_none=True, example='', description='CIDR IPv4 address range',
    #                        context='query', )

    @validates_schema
    def validate_unsupported_parameters(self, data, *args, **kvargs):
        keys = data.keys()
        print("keys=%s" % keys)
        if (
            "FromPort" in keys
            or "ToPort" in keys
            or "IpProtocol" in keys
            or "SourceSecurityGroupName" in keys
            or "SourceSecurityGroupOwnerId" in keys
            or "CidrIp" in keys
        ):
            raise ValidationError(
                "Parameters FromPort, ToPort, IpProtocol, SourceSecurityGroupName, "
                "SourceSecurityGroupOwnerId, CidrIp are not supported. Use the parameter "
                "IpPermissions.N parameter"
            )


class AuthorizeSGroupEgressApiRequestSchema(Schema):
    rule = fields.Nested(AuthorizeSGroupEgressParamsApiRequestSchema, context="body")


class AuthorizeSGroupEgressApiBodyRequestSchema(Schema):
    body = fields.Nested(AuthorizeSGroupEgressApiRequestSchema, context="body")


class AuthorizeSecurityGroupEgress(ServiceApiView):
    summary = "Add rule outbound for security group"
    description = "Add rule outbound for security group"
    tags = ["computeservice"]
    definitions = {
        "AuthorizeSGroupEgressApiRequestSchema": AuthorizeSGroupEgressApiRequestSchema,
        "AuthorizeSGroupEgressApiResponseSchema": AuthorizeSGroupEgressApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(AuthorizeSGroupEgressApiBodyRequestSchema)
    parameters_schema = AuthorizeSGroupEgressApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            202: {
                "description": "success",
                "schema": AuthorizeSGroupEgressApiResponseSchema,
            }
        }
    )
    response_schema = AuthorizeSGroupEgressApiResponseSchema

    def post(self, controller, data, *args, **kwargs):
        data = data.get("rule")
        sg_uuid = data.get("GroupName", None)

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        return_value = type_plugin.aws_create_rule(type_plugin.instance, data, __RULE_GROUP_EGRESS__)

        res = {
            "AuthorizeSecurityGroupEgressResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "Return": return_value,
                "nvl-activeTask": type_plugin.active_task,
            }
        }
        return res, 202


class AuthorizeSGroupIngressApi1ResponseSchema(Schema):
    Return = fields.Boolean(required=True, example=True, allow_none=False, data_key="return")
    requestId = fields.String(required=True, example="", allow_none=True)
    nvl_activeTask = fields.String(
        required=True,
        allow_none=True,
        data_key="nvl-activeTask",
        description="active task id",
    )


class AuthorizeSGroupIngressApiResponseSchema(Schema):
    AuthorizeSecurityGroupIngressResponse = fields.Nested(
        AuthorizeSGroupIngressApi1ResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class AuthorizeSGroupIngressParamsApiRequestSchema(Schema):
    # GroupId = fields.String(required=False, allow_none=True, example='', description='id of the security group',
    #                         context='query')
    GroupName = fields.String(
        required=False,
        example="",
        description="name of the security group",
        context="query",
    )
    IpPermissions_N = fields.List(
        fields.Nested(IpPermissionsParameterRequestSchema),
        required=False,
        collection_format="multi",
        data_key="IpPermissions.N",
        description="sets of ip permission",
        context="query",
    )

    # deprecated
    # FromPort = fields.Integer(required=False, allow_none=True, example='',
    #                           description='start of port range for the protocols (TPC)', context='query')
    # ToPort = fields.Integer(required=False, allow_none=True, example='',
    #                         description='end of port range for the protocols', context='query')
    # IpProtocol = fields.String(required=False, allow_none=True,
    #                            validate=OneOf(['tcp', 'udp', 'icmp', '-1']),
    #                            description='IP protocol for security group rule', context='query', )
    # SourceSecurityGroupName = fields.String(required=False, allow_none=True, example='',
    #                                         description='name of the source security group', context='query')
    # CidrIp = fields.String(required=False, allow_none=True, example='', description='CIDR IPv4 address range',
    #                        context='query', )

    @validates_schema
    def validate_unsupported_parameters(self, data, *args, **kvargs):
        keys = data.keys()
        print("keys=%s" % keys)
        if (
            "FromPort" in keys
            or "ToPort" in keys
            or "IpProtocol" in keys
            or "SourceSecurityGroupName" in keys
            or "CidrIp" in keys
        ):
            raise ValidationError(
                "The FromPort, ToPort, IpProtocol, SourceSecurityGroupName, "
                "CidrIp parameters are not supported, please use the IpPermissions.N parameter"
            )


class AuthorizeSGroupIngressApiRequestSchema(Schema):
    rule = fields.Nested(AuthorizeSGroupIngressParamsApiRequestSchema, context="body")


class AuthorizeSGroupIngressApiBodyRequestSchema(Schema):
    body = fields.Nested(AuthorizeSGroupIngressApiRequestSchema, context="body")


class AuthorizeSecurityGroupIngress(ServiceApiView):
    summary = "Add rule inbound for security group"
    description = "Add rule inbound for security group"
    tags = ["computeservice"]
    definitions = {
        "AuthorizeSGroupIngressApiRequestSchema": AuthorizeSGroupIngressApiRequestSchema,
        "AuthorizeSGroupIngressApiResponseSchema": AuthorizeSGroupIngressApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(AuthorizeSGroupIngressApiBodyRequestSchema)
    parameters_schema = AuthorizeSGroupIngressApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            202: {
                "description": "success",
                "schema": AuthorizeSGroupIngressApiResponseSchema,
            }
        }
    )
    response_schema = AuthorizeSGroupIngressApiResponseSchema

    def post(self, controller, data, *args, **kwargs):
        data = data.get("rule")
        sg_uuid = data.get("GroupName", None)

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        return_value = type_plugin.aws_create_rule(type_plugin.instance, data, __RULE_GROUP_INGRESS__)

        res = {
            "AuthorizeSecurityGroupIngressResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "return": return_value,
                "nvl-activeTask": type_plugin.active_task,
            }
        }
        return res, 202


class RevokeSGroupEgressApi1ResponseSchema(Schema):
    # Return is return in aws
    Return = fields.Boolean(required=True, example=True, allow_none=False)
    requestId = fields.String(required=True, allow_none=True)
    nvl_activeTask = fields.String(
        required=True,
        allow_none=True,
        data_key="nvl-activeTask",
        description="active task id",
    )


class RevokeSGroupEgressApiResponseSchema(Schema):
    RevokeSecurityGroupEgressResponse = fields.Nested(
        RevokeSGroupEgressApi1ResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class RevokeSGroupEgressParamsApiRequestSchema(Schema):
    # GroupId = fields.String(required=True, example='', description='id of the security group')
    GroupName = fields.String(
        required=False,
        example="",
        description="name of the security group",
        context="query",
    )
    IpPermissions_N = fields.List(
        fields.Nested(IpPermissionsParameterRequestSchema),
        required=False,
        context="query",
        collection_format="multi",
        data_key="IpPermissions.N",
        description="sets of ip permission",
    )

    @validates_schema
    def validate_unsupported_parameters(self, data, *args, **kvargs):
        keys = data.keys()
        print("keys=%s" % keys)
        if (
            "FromPort" in keys
            or "ToPort" in keys
            or "IpProtocol" in keys
            or "SourceSecurityGroupName" in keys
            or "SourceSecurityGroupOwnerId" in keys
            or "CidrIp" in keys
        ):
            raise ValidationError(
                "Parameters FromPort, ToPort, IpProtocol, SourceSecurityGroupName, "
                "SourceSecurityGroupOwnerId, CidrIp are not supported. Use the parameter "
                "IpPermissions.N parameter"
            )


class RevokeSGroupEgressApiRequestSchema(Schema):
    rule = fields.Nested(RevokeSGroupEgressParamsApiRequestSchema, context="body")


class RevokeSGroupEgressApiBodyRequestSchema(Schema):
    body = fields.Nested(RevokeSGroupEgressApiRequestSchema, context="body")


class RevokeSecurityGroupEgress(ServiceApiView):
    summary = "Delete rule outbound for security group"
    description = "Delete rule outbound for security group"
    tags = ["computeservice"]
    definitions = {
        "RevokeSGroupEgressApiRequestSchema": RevokeSGroupEgressApiRequestSchema,
        "RevokeSGroupEgressApiResponseSchema": RevokeSGroupEgressApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(RevokeSGroupEgressApiBodyRequestSchema)
    parameters_schema = RevokeSGroupEgressApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {202: {"description": "success", "schema": RevokeSGroupEgressApiResponseSchema}}
    )
    response_schema = RevokeSGroupEgressApiResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        data = data.get("rule")
        sg_uuid = data.get("GroupName", None)

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        return_value = type_plugin.aws_delete_rule(type_plugin.instance, data, __RULE_GROUP_EGRESS__)

        res = {
            "RevokeSecurityGroupEgressResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "Return": return_value,
                "nvl-activeTask": type_plugin.active_task,
            }
        }
        return res, 202


class RevokeSGroupIngressApi1ResponseSchema(Schema):
    # Return is return in aws
    Return = fields.Boolean(required=True, example=True, allow_none=False)
    requestId = fields.String(required=True, example="", allow_none=True)
    nvl_activeTask = fields.String(
        required=True,
        allow_none=True,
        data_key="nvl-activeTask",
        description="active task id",
    )


class RevokeSGroupIngressApiResponseSchema(Schema):
    RevokeSecurityGroupIngressResponse = fields.Nested(
        RevokeSGroupIngressApi1ResponseSchema,
        required=True,
        many=False,
        allow_none=False,
    )


class RevokeSGroupIngressParamsApiRequestSchema(Schema):
    # GroupId = fields.String(required=False, allow_none=True, example='', description='id of the security group',
    #                         context='query')
    GroupName = fields.String(
        required=False,
        example="",
        description="name of the security group",
        context="query",
    )
    IpPermissions_N = fields.List(
        fields.Nested(IpPermissionsParameterRequestSchema),
        required=False,
        collection_format="multi",
        data_key="IpPermissions.N",
        description="sets of ip permission",
        context="query",
    )

    @validates_schema
    def validate_unsupported_parameters(self, data, *args, **kvargs):
        keys = data.keys()
        print("keys=%s" % keys)
        if (
            "FromPort" in keys
            or "ToPort" in keys
            or "IpProtocol" in keys
            or "SourceSecurityGroupName" in keys
            or "CidrIp" in keys
        ):
            raise ValidationError(
                "The FromPort, ToPort, IpProtocol, SourceSecurityGroupName, "
                "CidrIp parameters are not supported, please use the IpPermissions.N parameter"
            )


class RevokeSGroupIngressApiRequestSchema(Schema):
    rule = fields.Nested(RevokeSGroupIngressParamsApiRequestSchema, context="body")


class RevokeSGroupIngressApiBodyRequestSchema(Schema):
    body = fields.Nested(RevokeSGroupIngressApiRequestSchema, context="body")


class RevokeSecurityGroupIngress(ServiceApiView):
    summary = "Delete rule inbound for security group"
    description = "Delete rule inbound for security group"
    tags = ["computeservice"]
    definitions = {
        "RevokeSGroupIngressApiRequestSchema": RevokeSGroupIngressApiRequestSchema,
        "RevokeSGroupIngressApiResponseSchema": RevokeSGroupIngressApiResponseSchema,
    }
    parameters = SwaggerHelper().get_parameters(RevokeSGroupIngressApiBodyRequestSchema)
    parameters_schema = RevokeSGroupIngressApiRequestSchema
    responses = SwaggerApiView.setResponses(
        {
            202: {
                "description": "success",
                "schema": RevokeSGroupIngressApiResponseSchema,
            }
        }
    )
    response_schema = RevokeSGroupIngressApiResponseSchema

    def delete(self, controller, data, *args, **kwargs):
        data = data.get("rule")
        sg_uuid = data.get("GroupName", None)

        type_plugin = controller.get_service_type_plugin(sg_uuid)
        return_value = type_plugin.aws_delete_rule(type_plugin.instance, data, __RULE_GROUP_INGRESS__)

        res = {
            "RevokeSecurityGroupIngressResponse": {
                "__xmlns": self.xmlns,
                "requestId": operation.id,
                "Return": return_value,
                "nvl-activeTask": type_plugin.active_task,
            }
        }
        return res, 202


class NetworkSecurityGroupAPI(ApiView):
    @staticmethod
    def register_api(module, dummyrules=None, **kwargs):
        base = module.base_path + "/networkservices/vpc"
        rules = [
            ("%s/deletesecuritygroup" % base, "DELETE", DeleteSecurityGroup, {}),
            ("%s/createsecuritygroup" % base, "POST", CreateSecurityGroup, {}),
            ("%s/patchsecuritygroup" % base, "PATCH", PatchSecurityGroup, {}),
            ("%s/describesecuritygroups" % base, "GET", DescribeSecurityGroups, {}),
            (
                "%s/authorizesecuritygroupingress" % base,
                "POST",
                AuthorizeSecurityGroupIngress,
                {},
            ),
            (
                "%s/authorizesecuritygroupegress" % base,
                "POST",
                AuthorizeSecurityGroupEgress,
                {},
            ),
            (
                "%s/revokesecuritygroupingress" % base,
                "DELETE",
                RevokeSecurityGroupIngress,
                {},
            ),
            (
                "%s/revokesecuritygroupegress" % base,
                "DELETE",
                RevokeSecurityGroupEgress,
                {},
            ),
        ]

        ApiView.register_api(module, rules, **kwargs)
