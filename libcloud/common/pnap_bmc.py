# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
phoenixNAP BMC Common Components
"""
from base64 import standard_b64encode
from libcloud.utils.py3 import httplib
from libcloud.common.base import JsonResponse, ConnectionUserAndKey, LibcloudError
from libcloud.compute.types import NodeState, InvalidCredsError

AUTH_API = "https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token"  # noqa

API_ENDPOINTS = {
    "NODE": "/bmc/v1/servers/",
    "KEY_PAIR": "/bmc/v1/ssh-keys/",
    "TAG": "/tag-manager/v1/tags/",
    "IP_BLOCK": "/ips/v1/ip-blocks/",
    "PRIVATE_NETWORK": "/networks/v1/private-networks/",
    "PUBLIC_NETWORK": "/networks/v1/public-networks/",
    "PRODUCT": "billing/v1/products/",
    "PRODUCT_AVAILABILITY": "/billing/v1/product-availability/",
    "ACCOUNT_BILLING": "/billing/v1/account-billing-configurations/me/",
    "RATED-USAGE": "/billing/v1/rated-usage/",
    "RATED-USAGE-CURRENT": "/billing/v1/rated-usage/month-to-date/",
    "EVENT": "/audit/v1/events/",
    "RESERVATION": "/billing/v1/reservations/",
    "CLUSTER": "/solutions/rancher/v1beta/clusters/",
    "STORAGE_NETWORK": "/network-storage/v1/storage-networks/",
}

NODE_STATE_MAP = {
    "creating": NodeState.PENDING,
    "rebooting": NodeState.PENDING,
    "resetting": NodeState.PENDING,
    "powered-on": NodeState.RUNNING,
    "powered-off": NodeState.STOPPED,
    "error": NodeState.ERROR,
}

VALID_RESPONSE_CODES = [
    httplib.OK,
    httplib.ACCEPTED,
    httplib.CREATED,
    httplib.NO_CONTENT,
]


class PnapBmcResponse(JsonResponse):
    """
    PNAP_BMC API Response
    """

    def parse_error(self):
        if self.status == httplib.UNAUTHORIZED:
            raise InvalidCredsError("Authorization Failed")
        if self.status == httplib.NOT_FOUND:
            raise Exception("The resource you are looking for is not found.")
        if self.status != httplib.OK:
            body = self.parse_body()
            err = "Missing an error message"
            if "message" in body:
                ve = str(body.get("validationErrors") or "")
                err = "%s %s" % (body.get("message"), ve)
            raise PnapBmcAPIException(
                code=self.status, msg=err, driver=self.connection.driver
            )

    def success(self):
        return self.status in VALID_RESPONSE_CODES


class PnapBmcAPIException(LibcloudError):
    def __init__(self, code, msg, driver):
        self.code = code
        self.msg = msg
        self.driver = driver

    def __str__(self):
        return "%s: %s" % (self.code, self.msg)

    def __repr__(self):
        return "<PnapBmcAPIException: code='%s', msg='%s'>" % (
            self.code,
            self.msg,
        )


class PnapBmcConnection(ConnectionUserAndKey):
    """
    Connection class for the PNAP_BMC driver.
    """

    host = "api.phoenixnap.com"
    responseCls = PnapBmcResponse
    token = None

    def add_default_headers(self, headers):
        if self.token is None:
            self._get_auth_token()
        headers.update({"Content-Type": "application/json"})
        headers.update({"Authorization": "Bearer %s" % self.token})
        return headers

    def _get_auth_token(self):
        body = {"grant_type": "client_credentials"}
        self.connection.request(
            method="POST", url=AUTH_API, body=body, headers=self._get_auth_headers()
        )
        response = self.connection.getresponse()
        try:
            self.token = response.json()["access_token"]
        except KeyError:
            raise InvalidCredsError() from None

    def _get_auth_headers(self):
        auth_data = "%s:%s" % (self.user_id, self.key)
        basic_auth = standard_b64encode(auth_data.encode("utf-8"))
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic %s" % basic_auth.decode("utf-8"),
        }


class PnapBmcTag:
    """
    A representation of a Tag in phoenixNAP BMC
    Tags are case-sensitive key-value pairs that simplify resource management.
    """

    def __init__(
        self,
        id,
        name,
        is_billing_tag,
        description,
        values,
        resource_assignments,
        created_by,
    ):
        """
        Initialize an instance of :class:`PnapBmcTag`

        :param id: The unique id of the tag.
        :type  id: ``str``

        :param name: The name of the tag.
        :type  name: ``str``

        :param values: The optional values of the tag.
        :type  values: ``list`` of ``str``

        :param description: The description of the tag.
        :type  description: ``str``

        :param is_billing_tag: Whether or not to show the tag
                               as part of billing and invoices.
        :type  is_billing_tag: ``bool``

        :param resource_assignments: Resource assigned to a tag.
        :type  resource_assignments: ``list`` of ``dict``

        :param created_by: The tag's creator.
        :type  created_by: ``str``
        """

        self.id = id
        self.name = name
        self.is_billing_tag = is_billing_tag
        self.description = description
        self.values = values
        self.resource_assignments = resource_assignments
        self.created_by = created_by

    def __repr__(self):
        return (
            "<PnapBmcTag: id=%s, name=%s, is_billing_tag=%s, description=%s,"
            "values=%s, resource_assignments=%s, created_by=%s>"
            % (
                self.id,
                self.name,
                self.is_billing_tag,
                self.description,
                self.values,
                self.resource_assignments,
                self.created_by,
            )
        )


class PnapBmcIpBlock:
    """
    A representation of a IP Block in phoenixNAP BMC
    Public IP blocks are a set of contiguous IPs that allow
    you to access your servers or networks from the internet.
    """

    def __init__(
        self,
        id,
        location,
        cidr_block_size,
        cidr,
        status,
        assigned_resource_id,
        assigned_resource_type,
        description,
        tags,
        is_bring_your_own,
        created_on,
    ):
        """
        Initialize an instance of :class:`PnapBmcIpBlock`

        :param id: IP Block identifier.
        :type  id: ``str``TAG
        :param assigned_resource_id: ID of the resource
                                     assigned to the IP Block.
        :type  assigned_resource_id: ``str``

        :param assigned_resource_type: Type of the resource
                                       assigned to the IP Block.
        :type  assigned_resource_type: ``str``

        :param description: The description of the IP Block.
        :type  description: ``str``

        :param tags: The tags assigned if any.
        :type  tags: ``list`` of ``dict``

        :param is_bring_your_own: True if the IP block
                                  is a bring your own block.
        :type  is_bring_your_own: ``bool``

        :param created_on: Date and time when the IP block was created.
        :type  created_on: ``str``
        """
        self.id = id
        self.location = location
        self.cidr_block_size = cidr_block_size
        self.cidr = cidr
        self.status = status
        self.assigned_resource_id = assigned_resource_id
        self.assigned_resource_type = assigned_resource_type
        self.description = description
        self.tags = tags
        self.is_bring_your_own = is_bring_your_own
        self.created_on = created_on

    def __repr__(self):
        return (
            "<PnapBmcIpBlock: id=%s, location=%s, cidr_block_size=%s, cidr=%s,"
            "status=%s, assigned_resource_id=%s, assigned_resource_type=%s,"
            "description=%s, tags=%s, is_bring_your_own=%s, created_on=%s>"
            % (
                self.id,
                self.location,
                self.cidr_block_size,
                self.cidr,
                self.status,
                self.assigned_resource_id,
                self.assigned_resource_type,
                self.description,
                self.tags,
                self.is_bring_your_own,
                self.created_on,
            )
        )


class PnapBmcPrivateNetwork:
    """
    A representation of a Private Network in phoenixNAP BMC
    Use private networks to avoid unnecessary egress data charges.
    """

    def __init__(
        self,
        id,
        name,
        description,
        vlan_id,
        private_network_type,
        location,
        location_default,
        cidr,
        memberships,
        created_on,
    ):
        """
        Initialize an instance of :class:`PnapBmcPrivateNetwork`

        :param id: The private network identifier.
        :type  id: ``str``

        :param name: The friendly name of private network.
        :type  name: ``str``

        :param description: The description of private network.
        :type  description: ``str``

        :param vlan_id: The VLAN of private network.
        :type  vlan_id: ``str``

        :param private_network_type: The type of the private network.
        :type  private_network_type: ``str``

        :param location: The location of private network.
        :type  location: ``str``

        :param location_default: Identifies network as the default
                                 private network for the specified location.
        :type  location_default: ``bool``

        :param cidr: IP range associated with this
                     private network in CIDR notation.
        :type  cidr: ``str``

        :param memberships: Resource details linked to the Network.
        :type  memberships: ``list`` of ``dict``

        :param created_on: Date and time when this private network was created.
        :type  created_on: ``str``
        """

        self.id = id
        self.name = name
        self.description = description
        self.vlan_id = vlan_id
        self.private_network_type = private_network_type
        self.location = location
        self.location_default = location_default
        self.cidr = cidr
        self.memberships = memberships
        self.created_on = created_on

    def __repr__(self):
        return (
            "<PnapBmcPrivateNetwork: id=%s, name=%s, description=%s,"
            "vlan_id=%s, private_network_type=%s, location=%s,"
            "location_default=%s, cidr=%s, memberships=%s created_on=%s>"
            % (
                self.id,
                self.name,
                self.description,
                self.vlan_id,
                self.private_network_type,
                self.location,
                self.location_default,
                self.cidr,
                self.memberships,
                self.created_on,
            )
        )


class PnapBmcPublicNetwork:
    """
    A representation of a Public Network in phoenixNAP BMC
    Use public networks to place multiple servers on the same network or VLAN.
    Assign new servers with IP addresses from the same CIDR range.
    """

    def __init__(
        self,
        id,
        name,
        description,
        vlan_id,
        memberships,
        location,
        ip_blocks,
        created_on,
    ):
        """
        Initialize an instance of :class:`PnapBmcPublicNetwork`

        :param id: The public network identifier.
        :type  id: ``str``

        :param name: The friendly name of public network.
        :type  name: ``str``

        :param description: The description of public network.
        :type  description: ``str``

        :param vlan_id: The VLAN of this public network.
        :type  vlan_id: ``str``

        :param memberships: A list of resources that are
                            members of public network.
        :type  memberships: ``list`` of ``dict``

        :param location: The location of public network.
        :type  location: ``str``

        :param ip_blocks: A list of IP Blocks that are
                          associated with public network.
        :type  ip_blocks: ``list`` of ``dict``

        :param created_on: Date and time when public network was created.
        :type  created_on: ``str``
        """

        self.id = id
        self.name = name
        self.description = description
        self.vlan_id = vlan_id
        self.memberships = memberships
        self.location = location
        self.ip_blocks = ip_blocks
        self.created_on = created_on

    def __repr__(self):
        return (
            "<PnapBmcPublicNetwork: id=%s, name=%s, description=%s,"
            "vlan_id=%s, memberships=%s, location=%s,"
            "ip_blocks=%s, created_on=%s>"
            % (
                self.id,
                self.name,
                self.description,
                self.vlan_id,
                self.memberships,
                self.location,
                self.ip_blocks,
                self.created_on,
            )
        )


class PnapBmcStorageNetwork:
    """
    A representation of a Storage Network in phoenixNAP BMC.
    Use storage networks to expand storage capacity on a private network.
    """

    def __init__(
        self,
        id,
        name,
        description,
        status,
        location,
        network_id,
        ips,
        created_on,
        volumes,
    ):
        """
        Initialize an instance of :class:`PnapBmcStorageNetwork`

        :param id: Storage network ID.
        :type  id: ``str``

        :param name: Storage network friendly name.
        :type  name: ``str``

        :param description: Storage network description.
        :type  description: ``str``

        :param status: Status of the resource.
        :type  status: ``str``

        :param location: The location of storage network.
        :type  location: ``str``

        :param network_id: Id of network the storage belongs to.
        :type  network_id: ``str``

        :param ips: IP of the storage network.
        :type  ips: ``list`` of ``str``

        :param created_on: Date and time when this storage network was created.
        :type  created_on: ``str``

        :param volumes: Volume for a storage network.
        :type  volumes: ``list`` of ``dict``
        """

        self.id = id
        self.name = name
        self.description = description
        self.status = status
        self.location = location
        self.network_id = network_id
        self.ips = ips
        self.created_on = created_on
        self.volumes = volumes

    def __repr__(self):
        return (
            "<PnapBmcStorageNetwork: id=%s, name=%s, description=%s,"
            "status=%s, location=%s, network_id=%s, ips=%s,"
            "created_on=%s, volumes=%s>"
            % (
                self.id,
                self.name,
                self.description,
                self.status,
                self.location,
                self.network_id,
                self.ips,
                self.created_on,
                self.volumes,
            )
        )


PNAP_BMC_TYPES = {
    "tag": PnapBmcTag,
    "ip_block": PnapBmcIpBlock,
    "private_network": PnapBmcPrivateNetwork,
    "public_network": PnapBmcPublicNetwork,
    "storage_network": PnapBmcStorageNetwork,
}
