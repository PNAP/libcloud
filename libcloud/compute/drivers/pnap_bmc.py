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
PNAP_BMC Cloud driver (https://phoenixnap.com/)
"""
import json
import os
from libcloud.common.pnap_bmc import (
    API_ENDPOINTS,
    PNAP_BMC_TYPES,
    VALID_RESPONSE_CODES,
    NODE_STATE_MAP,
    PnapBmcConnection,
    PnapBmcTag,
    PnapBmcIpBlock,
    PnapBmcPrivateNetwork,
    PnapBmcPublicNetwork,
)
from libcloud.compute.providers import Provider
from libcloud.compute.base import (
    Node,
    NodeDriver,
    NodeImage,
    NodeSize,
    NodeLocation,
    KeyPair,
)


class PnapBmcNodeDriver(NodeDriver):
    """
    PNAP_BMC NodeDriver
    >>> from libcloud.compute.providers import get_driver
    >>> driver = get_driver(Provider.PNAP_BMC)
    >>> conn = driver('Client ID','Client Secret')
    >>> conn.list_nodes()
    """

    type = Provider.PNAP_BMC
    name = "PNAP_BMC"
    website = "https://www.phoenixnap.com/"
    connectionCls = PnapBmcConnection

    def list_locations(self):
        """
        List available locations.

        :rtype: ``list`` of :class:`NodeLocation`
        """
        return [
            NodeLocation("PHX", "PHOENIX", "US", self),
            NodeLocation("ASH", "ASHBURN", "US", self),
            NodeLocation("NLD", "AMSTERDAM", "NLD", self),
            NodeLocation("SGP", "SINGAPORE", "SGP", self),
            NodeLocation("CHI", "CHICAGO", "CHI", self),
            NodeLocation("SEA", "SEATTLE", "SEA", self),
            NodeLocation("AUS", "AUSTIN", "AUS", self),
        ]

    def list_images(self, location=None):
        """
        List available operating systems.

        :rtype: ``list`` of :class:`NodeSize`
        """
        return [
            NodeImage("ubuntu/bionic", "ubuntu/bionic", self),
            NodeImage("ubuntu/focal", "ubuntu/focal", self),
            NodeImage("centos/centos7", "centos/centos7", self),
            NodeImage("windows/srv2019std", "windows/srv2019std", self),
            NodeImage("windows/srv2019dc", "windows/srv2019dc", self),
            NodeImage("esxi/esxi70u2", "esxi/esxi70u2", self),
            NodeImage("debian/bullseye", "debian/bullseye", self),
            NodeImage("proxmox/bullseye", "proxmox/bullseye", self),
        ]

    def list_sizes(self, location=None):
        """
        List available server types.

        :return: List of images available
        :rtype: ``list`` of :class:`NodeImage`
        """
        if isinstance(location, NodeLocation):
            location = location.id
        sizes = []
        url = "billing/v1/products?productCategory=SERVER"
        servers = self.connection.request(url).object
        for ser in servers:
            locations = set()
            [locations.add(plan["location"]) for plan in ser["plans"]]
            if location is None or location in locations:
                sizes.append(
                    NodeSize(
                        ser["productCode"],
                        ser["productCode"],
                        ser["metadata"]["ramInGb"] * 1000,
                        None,
                        None,
                        None,
                        self,
                    )
                )
        return sizes

    def list_nodes(self):
        """
        List all your existing compute nodes.

        :rtype: ``list`` of :class:`Node`
        """
        return self._list_resources("node")

    def reboot_node(self, node):
        """
        Reboot a node.

        :keyword node: The node to reboot
        :type    node: :class:`Node`

        :rtype: ``bool``
        """
        return self._node_action(node, "reboot")

    def start_node(self, node):
        """
        Start a node.

        :keyword node: Node which should be used
        :type    node: :class:`Node`

        :rtype: ``bool``
        """
        return self._node_action(node, "power-on")

    def stop_node(self, node):
        """
        Stop a specific node.

        :param node: Node which should be used
        :type  node: :class:`Node`

        :rtype: ``bool``
        """
        return self._node_action(node, "shutdown")

    def destroy_node(self, node, ex_delete_ip_blocks=True):
        """
        Delete a specific node.
        This is an irreversible action, and once performed,
        no data can be retrieved.

        :keyword ex_delete_ip_blocks: Determines whether the IP blocks
                                      assigned to the server should be
                                      deleted or not.
        :type    ex_delete_ip_blocks: ``bool``

        :keyword node: The node to delete
        :type    node: :class:`Node`
        :rtype: ``bool``
        """
        data = {"deleteIpBlocks": ex_delete_ip_blocks}
        return self._node_action(node, "deprovision", data)

    def create_node(
        self,
        name,
        size,
        image,
        location,
        ex_ip_blocks_configuration_type=None,
        ex_ip_blocks_id=None,
        ex_management_access_allowed_ips=None,
        ex_gateway_address=None,
        ex_private_network_configuration_type=None,
        ex_private_networks=None,
        ex_public_networks=None,
        ex_tags=None,
        ex_description=None,
        ex_ssh_keys=None,
        ex_install_default_ssh_keys=True,
        ex_ssh_key_ids=None,
        ex_reservation_id=None,
        ex_pricing_model="HOURLY",
        ex_network_type="PUBLIC_AND_PRIVATE",
        ex_rdp_allowed_ips=None,
    ):
        """
        Create a node.

        :keyword ex_ip_blocks_configuration_type: Determines the approach for
                                                 configuring IP blocks for
                                                 the server being provisioned.
        :type    ip_blocks_configuration_type: ``str``

        :keyword ex_ip_blocks_id: Used to specify the previously purchase
                                  IP blocks to assign to this server upon
                                  provisioning.
        :type    ex_ip_blocks_id: ``list`` of ``dict``
                                  ip_blocks elements: id (``str``)

        :keyword ex_management_access_allowed_ips: List of IPs allowed to
                                                   access the Management UI.
                                                   Supported in single IP,
                                                   CIDR and range format.
        :type    ex_management_access_allowed_ips: ``list`` of ``str``

        :keyword ex_gateway_address: The address of the gateway assigned
                                     / to assign to the server.
        :type    ex_gateway_address: ``str``

        :keyword ex_private_network_configuration_type: Determines the
                                                        approach for
                                                        configuring
                                                        private network(s)
                                                        for the server being
                                                        provisioned.
        :type    ex_private_network_configuration_type: ``str``

        :keyword ex_private_networks: The list of private networks
                                      this server is member of.
                                      Private networks elements:
                                        id (``str``),
                                        ips, (``list`` of ``str``)
                                        dhcp (``bool``)
        :type    ex_private_networks: ``list`` of ``dict``

        :keyword ex_public_networks: The list of public networks
                                     this server is member of.
                                     Public networks elements:
                                       id (``str``),
                                       ips (``list`` of ``str``)
        :type    ex_public_networks: ``list`` of ``dict``

        :keyword ex_tags: Tags to set to server, if any.
                          Tag elements:
                            name (``str``),
                            value (``str``)
        :type    ex_tags: ``list`` of ``dict``

        :keyword ex_description: Description of server.
        :type    ex_description: ``str``

        :keyword ex_install_default_ssh_keys: Whether or not to install
                                              ssh keys marked as default
                                              in addition to any ssh keys
                                              specified in this request.
        :type    ex_install_default_ssh_keys: ``bool``

        :keyword ex_ssh_keys: A list of SSH Keys that will be
                              installed on the server.
        :type    ex_ssh_keys: ``list`` of ``str``

        :keyword ex_ssh_key_ids: A list of SSH Key IDs that will be installed
                                 on the server in addition to any ssh keys
                                 specified in this request.
        :type    ex_ssh_key_ids: ``list`` of ``str``

        :keyword ex_reservation_id: Server reservation ID.
        :type    ex_reservation_id: ``str``

        :keyword ex_pricing_model: Server pricing model.
        :type    ex_pricing_model: ``str``

        :keyword ex_network_type: The type of network configuration
                                  for this server.
        :type    ex_network_type: ``str``

        :keyword ex_rdp_allowed_ips: List of IPs allowed for RDP access to
                                     Windows OS. Supported in single IP, CIDR
                                     and range format. When undefined, RDP is
                                     disabled. To allow RDP access from any IP
                                     use 0.0.0.0/0
        :type    ex_rdp_allowed_ips: ``list`` of ``str``

        :return: The newly created node.
        :rtype: :class:`Node`
        """
        data = {
            "hostname": name,
            "type": size.id,
            "os": image.id,
            "location": location.id,
            "description": ex_description,
            "sshKeys": ex_ssh_keys,
            "sshKeyIds": ex_ssh_key_ids,
            "installDefaultSshKeys": ex_install_default_ssh_keys,
            "reservationId": ex_reservation_id,
            "pricingModel": ex_pricing_model,
            "networkType": ex_network_type,
            "networkConfiguration": {
                "gatewayAddress": ex_gateway_address,
                "privateNetworkConfiguration": {
                    "configurationType": ex_private_network_configuration_type,
                    "privateNetworks": ex_private_networks,
                },
                "ipBlocksConfiguration": {
                    "configurationType": ex_ip_blocks_configuration_type,
                    "ipBlocks": ex_ip_blocks_id,
                },
                "publicNetworkConfiguration": {"publicNetworks": ex_public_networks},
            },
            "osConfiguration": {
                "managementAccessAllowedIps": ex_management_access_allowed_ips,
                "windows": {"rdpAllowedIps": ex_rdp_allowed_ips},
            },
            "tags": ex_tags,
        }

        return self._create_resource("node", data)

    def list_key_pairs(self):
        """
        List all the available SSH keys.

        :return: Available SSH keys.
        :rtype: ``list`` of :class:`KeyPair`
        """
        return self._list_resources("key_pair")

    def get_key_pair(self, name):
        """
        Retrieve a single key pair.

        :param name: Name of the key pair to retrieve.
        :type  name: ``str``

        :rtype: :class:`.KeyPair` or `None`
        """
        return self._get_resource("key_pair", name)

    def import_key_pair_from_string(self, name, key_material, default=False):
        """
        Import a new public key from string.

        :param name: Key pair name.
        :type  name: ``str``

        :param key_material: Public key material.
        :type  key_material: ``str``

        :param default: Keys marked as default are always included
                        on server creation and reset unless
                        toggled off in creation/reset request.
        :type  default: ``bool``

        :return: Imported key pair object.
        :rtype: :class:`.KeyPair`
        """
        data = {"name": name, "key": key_material, "default": default}
        return self._create_resource("key_pair", data)

    def import_key_pair_from_file(self, name, key_file_path, default=False):
        """
        Import a new public key from file.

        :param name: Key pair name.
        :type  name: ``str``

        :param key_file_path: Path to the public key file.
        :type  key_file_path: ``str``

        :param default: Keys marked as default are always included
                        on server creation and reset unless
                        toggled off in creation/reset request.
        :type  default: ``bool``

        :return: Imported key pair object.
        :rtype: :class:`.KeyPair`
        """
        key_file_path = os.path.expanduser(key_file_path)

        with open(key_file_path, "r") as fp:
            key_material = fp.read().strip()

        return self.import_key_pair_from_string(
            name=name, key_material=key_material, default=default
        )

    def delete_key_pair(self, key_pair):
        """
        Delete an existing SSH key.
        :param: key_pair: SSH key (required)
        :type   key_pair: :class:`KeyPair`

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("key_pair", key_pair)

    def ex_edit_key_pair(self, key_pair, name=None, default=None):
        """
        Edit an existing SSH key.
        :param: key_pair: SSH key (required)
        :type:  key_pair: :class:`KeyPair`

        :param: name: New SSH Key name that can represent
                      the key as an alternative to it's ID.
        :type:  name: ``str``

        :param: default: Keys marked as default are always included
                         on server creation and reset unless toggled off
                         in creation/reset request.
        :type:  default: ``bool``

        :rtype: :class:`.KeyPair`
        """
        if name is None:
            name = key_pair.name
        if default is None:
            default = key_pair.extra["default"]
        data = {"name": name, "default": default}
        return self._edit_resource("key_pair", key_pair, data, method="PUT")

    def ex_power_off_node(self, node):
        """
        Power off a specific node
        (which is equivalent to cutting off electricity from the server).
        We strongly advise you to use the stop_node in order to minimize
        any possible data loss or corruption.

        :keyword node: Node which should be used
        :type    node: :class:`Node`
        :rtype: ``bool``
        """
        return self._node_action(node, "power-off")

    def ex_get_node_by_name(self, name):
        """
        Get a specific node by name

        :param name: Name of the node you want (required)
        :type  name: ``str``

        :rtype: :class:`Node` or `None`
        """
        return self._get_resource("node", name)

    def ex_edit_node(self, node, description=None, name=None):
        """
        Any changes to the hostname or description using the
        BMC API will reflect solely in the BMC API and portal.
        The changes are intended to keep the BMC data up to date with your server.
        We do not have access to your server's settings.
        Local changes to the server's hostname will not be reflected in the API or portal.

        :param name: Name of the node you want to edit(required)
        :type  name: ``str``

        :rtype: :class:`Node` or `None`
        """
        data = {"description": description, "hostname": name}
        return self._edit_resource("node", node, data)

    def ex_edit_node_tags(self, node, tags):
        """
        Overwrites tags assigned for Server and
        unassigns any tags not part of the request.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: tags: New tags. Elements:
                      name  (``str``),
                      value (``str``)
        :type:  tags: ``list`` of ``dict``

        :rtype: :class:``Node``
        """
        return self._edit_resource_by_id(
            "node", node.id, "/tags", data=tags, method="PUT"
        )

    def ex_edit_node_add_ip_block(self, node, ip_block, vlan_id=None):
        """
        Adds an IP block to this server.
        No actual configuration is performed on the operating system.
        BMC configures exclusively the networking
        devices in the datacenter infrastructure.
        Manual network configuration changes in the operating system
        of this server are required.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: ip_block: IP block which should be added.
        :type:  ip_block: :class:``PnapBmcIpBlock`` or
                          ``str`` (The IP block's ID.)

        :param: vlan_id: The VLAN on which this IP block has been
                         configured within the network switch.
        :type:  vlan_id: ``int``

        :rtype: ``dict``
        """
        if isinstance(ip_block, PnapBmcIpBlock):
            ip_block = ip_block.id

        data = {"id": ip_block, "vlanId": vlan_id}
        return self._edit_resource_by_id(
            "node",
            node.id,
            "/network-configuration/ip-block-configurations/ip-blocks",
            data=data,
            check_class=False,
        )

    def ex_edit_node_remove_ip_block(self, node, ip_block, delete_ip_block=False):
        """
        Removes the IP block from the server.
        No actual configuration is performed on the operating system.
        BMC configures exclusively the networking
        devices in the datacenter infrastructure.
        Manual network configuration changes in the operating system
        of this server are required.
        This is an advanced network action that can make your server
        completely unavailable over any network.
        Make sure this server is reachable over remote console
        for guaranteed access in case of misconfiguration.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: ip_block: IP block which should be added.
        :type:  ip_block: :class:``PnapBmcIpBlock`` or
                          ``str`` (The IP block's ID.)

        :param: delete_ip_block: Determines whether the IP blocks assigned
                                 to the server should be deleted or not.
        :type:  vlan_id: ``bool``

        :return: True on success
        :rtype: ``bool``
        """
        if isinstance(ip_block, PnapBmcIpBlock):
            ip_block = ip_block.id
        data = {"deleteIpBlocks": delete_ip_block}

        response = self._edit_resource_by_id(
            "node",
            node.id,
            "/network-configuration/ip-block-configurations/ip-blocks/",
            ip_block,
            data=data,
            method="DELETE",
            raw_response=True,
            check_class=False,
        )
        return response.status in VALID_RESPONSE_CODES

    def ex_edit_node_add_private_network(self, node, private_network):
        """
        Adds the server to a private network.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: private_network: Private Network which should be added.
                                 Private network elements:
                                   id (``str``),
                                   dhcp (``bool``),
                                   ips, (``list`` of ``str``)
                                 Example:
                                 {
                                    "id": "60473a6115e34466c9f8f083",
                                    "dhcp": "false",
                                    "ips": [
                                        "10.0.0.1",
                                        "10.0.0.2"
                                    ]
                                 }
        :type:  private_network: ``dict``

        :rtype: ``dict``
        """
        return self._edit_resource_by_id(
            "node",
            node.id,
            data=private_network,
            check_class=False,
            end_of_url="/network-configuration/private-network-configuration/private-networks",
        )

    def ex_edit_node_remove_private_network(self, node, private_network):
        """
        Removes the server from private network.
        No actual configuration is performed on the operating system.
        BMC configures exclusively the networking
        devices in the datacenter infrastructure.
        Manual network configuration changes in the operating system
        of this server are required.
        This is an advanced network action that can make your server
        completely unavailable over any network.
        Make sure this server is reachable over remote console
        for guaranteed access in case of misconfiguration.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: private_network: Private Network which should be removed.
        :type:  private_network: :class:``PnapBmcPrivateNetwork`` or
                                 ``str`` (The private network identifier.)

        :return: True on success
        :rtype: ``bool``
        """
        if isinstance(private_network, PnapBmcPrivateNetwork):
            private_network = private_network.id

        response = self._edit_resource_by_id(
            "node",
            node.id,
            "/network-configuration/private-network-configuration/private-networks/",
            private_network,
            method="DELETE",
            raw_response=True,
            check_class=False,
        )
        return response.status in VALID_RESPONSE_CODES

    def ex_edit_node_add_public_network(self, node, public_network):
        """
        Adds the server to a Public Network.
        No actual configuration is performed on the operating system.
        BMC configures exclusively the networking
        devices in the datacenter infrastructure.
        Manual network configuration changes in the operating system
        of this server are required.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: public_network: Public Network which should be added.
                                Public network elements:
                                  id (``str``),
                                  ips, (``list`` of ``str``)
                                 Example:
                                 {
                                    "id": "60473c2509268bc77fd06d29",
                                    "ips": [
                                        "182.16.0.146",
                                        "182.16.0.147"
                                    ]
                                 }
        :type:  public_network: ``dict``

        :rtype: ``dict``
        """
        return self._edit_resource_by_id(
            "node",
            node.id,
            data=public_network,
            check_class=False,
            end_of_url="/network-configuration/public-network-configuration/public-networks",
        )

    def ex_edit_node_remove_public_network(self, node, public_network):
        """
        Removes the server from the Public Network.
        No actual configuration is performed on the operating system.
        BMC configures exclusively the networking
        devices in the datacenter infrastructure.
        Manual network configuration changes in the operating system
        of this server are required.
        This is an advanced network action that can make your server
        completely unavailable over any network.
        Make sure this server is reachable over remote console
        for guaranteed access in case of misconfiguration.

        :param: node: Node which should be used
        :type:  node: :class:``Node``

        :param: public_network: Public Network which should be removed.
        :type:  public_network: :class:``PnapBmcPublicNetwork`` or
                                ``str`` (The Public Network identifier)

        :return: True on success
        :rtype: ``bool``
        """
        if isinstance(public_network, PnapBmcPublicNetwork):
            public_network = public_network.id

        response = self._edit_resource_by_id(
            "node",
            node.id,
            "/network-configuration/public-network-configuration/public-networks/",
            public_network,
            method="DELETE",
            raw_response=True,
            check_class=False,
        )
        return response.status in VALID_RESPONSE_CODES

    def ex_create_tag(self, name, description=None, is_billing_tag=False):
        """
        Create a tag with the provided information.

        :param: name: The unique name of the tag. (required)
        :type:  name: ``str``

        :param: description: The description of the tag.
        :type:  description: ``str``

        :param: is_billing_tag: Whether or not to show the tag as
                                part of billing and invoices.
        :type:  is_billing_tag: ``bool``

        :rtype: :class:`PnapBmcTag`
        """
        data = {
            "name": name,
            "isBillingTag": is_billing_tag,
            "description": description,
        }
        return self._create_resource("tag", data)

    def ex_list_tags(self):
        """
        Retrieve all tags belonging to the BMC Account.

        :rtype: ``list`` of :class:`PnapBmcTag`
        """
        return self._list_resources("tag")

    def ex_get_tag_by_name(self, name):
        """
        Get a specific tag key by name

        :param name: Name of the tag you want (required)
        :type  name: ``str``

        :rtype: :class:`PnapBmcTag` or `None`
        """

        return self._get_resource("tag", name)

    def ex_edit_tag(self, tag, name=None, is_billing_tag=None, description=None):
        """
        Edit an existing Tag.

        :param: tag:  The tag you want to edit (required)
        :type:  tag: :class:`PnapBmcTag`

        :param: name: New name of the tag.
        :type:  name: ``str``

        :param: is_billing_tag: Whether or not to show the tag
                                as part of billing and invoices.
        :type:  is_billing_tag: ``bool``

        :param: description: New description of the tag.
        :type:  description: ``str``

        :rtype: :class:`PnapBmcTag`
        """
        if name is None:
            name = tag.name
        if is_billing_tag is None:
            is_billing_tag = tag.is_billing_tag
        if description is None:
            description = tag.description
        data = {
            "name": name,
            "isBillingTag": is_billing_tag,
            "description": description,
        }
        return self._edit_resource("tag", tag, data)

    def ex_delete_tag(self, tag):
        """
        Delete an existing Tag.

        :param: tag: The tag you want to delete (required)
        :type   tag: :class:`PnapBmcTag`

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("tag", tag)

    def ex_create_ip_block(
        self, location, cidr_block_size, description=None, tags=None
    ):
        """
        Request an IP Block. An IP Block is a set of contiguous
        IPs that can be assigned to other resources such as servers.

        :param: location: IP Block location ID. (required)
        :type:  location: ``str``

        :param: cidr_block_size: CIDR IP Block Size. (required)
        :type:  cidr_block_size: ``str``

        :param: description: The description of the IP Block.
        :type:  description: ``str``

        :param: tags: Tags to set to ip-block, if any.
                      Tag elements:
                        name  (``str``),
                        value (``str``)
        :type:  tags: ``list`` of ``dict``

        :rtype: :class:`PnapBmcIpBlock`
        """
        data = {
            "location": location,
            "cidrBlockSize": cidr_block_size,
            "description": description,
            "tags": tags,
        }
        return self._create_resource("ip_block", data)

    def ex_list_ip_blocks(self):
        """
        List all IP Blocks.

        :rtype: ``list`` of :class:`PnapBmcIpBlock`
        """
        return self._list_resources("ip_block")

    def ex_get_ip_block_by_id(self, id):
        """
        Get a specific IP Block by id.

        :param id: The IP Block identifier.
        :type  id: ``str``

        :rtype: :class:`PnapBmcIpBlock` or `None`
        """
        return self._get_resource("ip_block", id)

    def ex_edit_ip_block_by_id(self, id, description):
        """
        Update IP Block's details.

        :param: id: IP Block identifier. (required)
        :type:  id: ``str``

        :param: description: New description of the IP Block. (required)
        :type:  description: ``str``

        :rtype: :class:`PnapBmcIpBlock`
        """
        data = {
            "description": description,
        }
        return self._edit_resource_by_id("ip_block", id, "", data=data, method="PATCH")

    def ex_edit_ip_block_tags_by_id(self, id, tags):
        """
        Overwrites tags assigned for IP Block and
        unassigns any tags not part of the request.

        :param: id: The unique id of the IP Block. (required)
        :type:  id: ``str``

        :param: tags: New tags. Elements:
                      name  (``str``),
                      value (``str``)
        :type:  tags: ``list`` of ``dict``

        :rtype: :class:`PnapBmcIpBlock`
        """
        return self._edit_resource_by_id(
            "ip_block", id, "/tags", data=tags, method="PUT"
        )

    def ex_delete_ip_block_by_id(self, id):
        """
        Delete an existing Ip Block.

        :param: id: The IP Block identifier. (required)
        :type   id: `str`

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("ip_block", id)

    def ex_create_private_network(
        self, name, location, cidr, location_default=False, description=None
    ):
        """
        Create a Private Network.

        :param: name: The friendly name of this private network. (required)
        :type:  name: ``str``

        :param: location: The location of private network. (required)
        :type:  location: ``str``

        :param: cidr: IP range associated with this private network
                      in CIDR notation. (required)
        :type:  cidr: ``str``

        :param: location_default: Identifies network as the default
                                  private network for the specified
                                  location.
        :type:  location_default: ``bool``

        :param: description: The description of private network.
        :type:  description: ``str``

        :rtype: :class:`PnapBmcPrivateNetwork`
        """
        data = {
            "name": name,
            "location": location,
            "locationDefault": location_default,
            "description": description,
            "cidr": cidr,
        }
        return self._create_resource("private_network", data)

    def ex_list_private_networks(self):
        """
        List all Private Networks owned by account.

        :rtype: ``list`` of :class:`PnapBmcPrivateNetwork`
        """
        return self._list_resources("private_network")

    def ex_get_private_network_by_name(self, name):
        """
        Get a specific Private Network by name

        :param name: Name of the Private Network you want (required)
        :type  name: ``str``

        :rtype: :class:`PnapBmcPrivateNetwork` or `None`
        """
        return self._get_resource("private_network", name)

    def ex_edit_private_network(
        self, private_network, name=None, description=None, location_default=None
    ):
        """
        Edit an existing Private Network.

        :param: private_network:  The Private Network you
                                  want to edit (required)
        :type:  private_network: :class:`PnapBmcPrivateNetwork`

        :param: name: New name of the Private Network.
        :type:  name: ``str``

        :param: description: New description of Private Network.
        :type:  description: ``str``

        :param: location_default: Identifies network as the default
                                  private network for the specified location.
        :type:  location_default: ``bool``

        :rtype: :class:`PnapBmcPrivateNetwork`
        """
        if name is None:
            name = private_network.name
        if location_default is None:
            location_default = private_network.location_default
        if description is None:
            description = private_network.description
        data = {
            "name": name,
            "locationDefault": location_default,
            "description": description,
        }
        return self._edit_resource("private_network", private_network, data, "PUT")

    def ex_delete_private_network(self, private_network):
        """
        Delete an existing Private Network.

        :param: private_network: The Private Network
                                 you want to delete (required)
        :type   private_network: :class:`PnapBmcPrivateNetwork`

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("private_network", private_network)

    def ex_create_public_network(
        self, name, location, description=None, ip_blocks=None
    ):
        """
        Create a Public Network.

        :param: name: The friendly name public network. (required)
        :type:  name: ``str``

        :param: location: The location of public network. (required)
        :type:  location: ``str``

        :param: description: The description of public network.
        :type:  description: ``str``

        :param: ip_blocks: A list of IP Blocks that will be
                           associated with this public network.
        :type:  ip_blocks: ``list`` of :class:``PnapBmcIpBlock`` or
                           ``list`` of ``dict`` : [{'id': '123'}, {'id': '456'}]

        :rtype: :class:`PnapBmcPublicNetwork`
        """
        if ip_blocks is not None:
            if isinstance(ip_blocks, PnapBmcIpBlock):
                ip_blocks = [ip_blocks]

            if all(isinstance(ip, PnapBmcIpBlock) for ip in ip_blocks):
                ip_blocks_prepared = []
                [ip_blocks_prepared.append({"id": ip.id}) for ip in ip_blocks]
                ip_blocks = ip_blocks_prepared

        data = {
            "name": name,
            "location": location,
            "description": description,
            "ipBlocks": ip_blocks,
        }
        return self._create_resource("public_network", data)

    def ex_list_public_networks(self):
        """
        List all Public Networks owned by account.

        :rtype: ``list`` of :class:`PnapBmcPublicNetwork`
        """
        return self._list_resources("public_network")

    def ex_get_public_network_by_name(self, name):
        """
        Get a specific Public Network by name

        :param name: Name of the Public Network you want (required)
        :type  name: ``str``

        :rtype: :class:`PnapBmcPublicNetwork` or `None`
        """
        return self._get_resource("public_network", name)

    def ex_edit_public_network(
        self,
        public_network,
        name=None,
        description=None,
    ):
        """
        Edit an existing Public Network.

        :param: public_network: The Public Network you
                                want to edit (required)
        :type:  public_network: :class:`PnapBmcPublicNetwork`

        :param: name: New name of the Public Network.
        :type:  name: ``str``

        :param: description: New description of Public Network.
        :type:  description: ``str``

        :rtype: :class:`PnapBmcPublicNetwork`
        """
        if name is None:
            name = public_network.name
        if description is None:
            description = public_network.description
        data = {
            "name": name,
            "description": description,
        }
        return self._edit_resource("public_network", public_network, data)

    def ex_edit_public_network_add_ip_block(self, public_network, ip_block_id):
        """
        Adds an IP block to public network.

        :param: public_network: The Public Network you
                                want to edit (required)
        :type:  public_network: :class:`PnapBmcPublicNetwork`

        :param: ip_block_id: The IP Block identifier.
        :type:  ip_block_id: ``str``

        :rtype: :class:`PnapBmcPublicNetwork`
        """
        data = {
            "id": ip_block_id,
        }
        response = self._edit_resource_by_id(
            "public_network",
            public_network.id,
            "/ip-blocks",
            data=data,
            raw_response=True,
            check_class=False,
        )

        if response.status in VALID_RESPONSE_CODES:
            return self.ex_get_public_network_by_name(public_network.name)

    def ex_edit_public_network_remove_ip_block(self, public_network, ip_block_id):
        """
        Removes the IP Block from the Public Network.
        The result of this is that any traffic addressed to any IP
        within the block will not be routed to this network anymore.
        Please ensure that no resource members within this network
        have any IPs assigned from the IP Block being removed.

        :param: public_network: The Public Network you
                                want to edit (required)
        :type:  public_network: :class:`PnapBmcPublicNetwork`

        :param: ip_block_id: The IP Block identifier.
        :type:  ip_block_id: ``str``

        :rtype: :class:`PnapBmcPublicNetwork`
        """
        response = self._edit_resource_by_id(
            "public_network",
            public_network.id,
            "/ip-blocks/",
            ip_block_id,
            method="DELETE",
            raw_response=True,
            check_class=False,
        )

        if response.status in VALID_RESPONSE_CODES:
            return self.ex_get_public_network_by_name(public_network.name)

    def ex_delete_public_network(self, public_network):
        """
        Delete an existing Public Network.

        :param: public_network: The Public Network
                                you want to delete (required)
        :type   public_network: :class:`PnapBmcPublicNetwork`

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("public_network", public_network)

    def ex_get_products(
        self, product_code=None, product_category=None, sku_code=None, location=None
    ):
        """
        Retrieves all Products.

        :param: product_code: The code identifying the product.
                              This code has significant across all locations.
        :type   product_code: ``str``

        :param: product_category: The product category.
        :type   product_category: ``str``

        :param: sku_code: The SKU identifying this pricing plan.
        :type   sku_code: ``str``

        :param: location: The code identifying the location.
        :type   location: ``str``

        :rtype: ``list`` of ``dict``
        """
        params = {
            "productCode": product_code,
            "productCategory": product_category,
            "skuCode": sku_code,
            "location": location,
        }

        return self._retrieve("product", params)

    def ex_get_product_availability(
        self,
        product_category=None,
        product_code=None,
        location=None,
        show_only_min_quantity_available=True,
        solution=None,
        min_quantity=None,
    ):
        """
        Retrieves all Products.

        :param: product_category: The product category.
        :type   product_category: ``list`` of ``str``

        :param: product_code: The code identifying the product.
                              This code has significant across all locations.
        :type   product_code: ``list`` of ``str``

        :param: show_only_min_quantity_available: Show only locations where
                                                  product with requested
                                                  quantity is available or all
                                                  locations where product
                                                  is offered.
        :type   show_only_min_quantity_available: ``bool``

        :param: location: The code identifying the location.
        :type   location: ``list`` of ``str``

        :param: solution: Solutions supported in specific
                          location for a product.
        :type   solution: ``list`` of ``str``

        :param: min_quantity: Minimal quantity of product needed.
        :type   min_quantity: ``int``

        :rtype: ``list`` of ``dict``
        """
        params = {
            "productCode": product_code,
            "productCategory": product_category,
            "showOnlyMinQuantityAvailable": show_only_min_quantity_available,
            "location": location,
            "minQuantity": min_quantity,
            "solution": solution,
        }
        return self._retrieve("product_availability", params)

    def ex_get_account_billing_configurations(self):
        """
        Retrieves billing configuration associated
        with the authenticated account.

        :rtype: ``dict``
        """
        return self._retrieve("account_billing")

    def ex_get_rated_usage(self, from_year_month, to_year_month, product_category=None):
        """
        Retrieves all rated usage for given time period.
        The information is presented as a list of rated usage records.
        Every record corresponds to a charge. All date & times are in UTC.

        :param: from_year_month: From year month (inclusive) to
                                 filter rated usage records by.
                                 Example: 2022-06
        :type   from_year_month: ``str``

        :param: to_year_month: To year month (inclusive) to filter
                               rated usage records by.
                               Example: 2022-07
        :type   to_year_month: ``str``

        :param: product_category: The product category.
        :type   product_category: ``str``

        :rtype: ``list`` of ``dict``
        """
        params = {
            "fromYearMonth": from_year_month,
            "toYearMonth": to_year_month,
            "productCategory": product_category,
        }
        return self._retrieve("rated-usage", params)

    def ex_get_rated_usage_month_to_date(self, product_category=None):
        """
        Retrieves all rated usage for the current calendar month.
        The information is presented as a list of rated usage records.
        Every record corresponds to a charge. All date & times are in UTC.

        :param: product_category: The product category.
        :type   product_category: ``str``

        :rtype: ``list`` of ``dict``
        """
        params = {"productCategory": product_category}
        return self._retrieve("rated-usage-current", params)

    def ex_get_events(
        self,
        from_date=None,
        to_date=None,
        limit=None,
        order=None,
        username=None,
        verb=None,
        uri=None,
    ):
        """
        Retrieves the event logs for given time period.
        All date & times are in UTC.

        :param: from_date: From the date and time (inclusive) to
                           filter event log records by.
                           Example: 2021-04-27T16:24:57.123Z
        :type   from_date: ``str``

        :param: to_date: To the date and time (inclusive) to
                         filter event log records by.
                         Example: 2021-04-29T16:24:57.123Z
        :type   to_date: ``str``

        :param: limit: Limit the number of records returned.
        :type   limit: ``int``

        :param: order: Ordering of the event's time.
                       The following values are allowed: ASC, DESC
        :type   order: ``str``

        :param: username: The username that did the actions.
        :type   username: ``str``

        :param: verb: The HTTP verb corresponding to the action.
                      The following values are allowed:
                      POST, PUT, PATCH, DELETE
        :type   verb: ``str``

        :param: uri: The request uri.
        :type   uri: ``str``

        :rtype: ``list`` of ``dict``
        """
        params = {
            "from": from_date,
            "to": to_date,
            "limit": limit,
            "order": order,
            "username": username,
            "verb": verb,
            "uri": uri,
        }
        return self._retrieve("event", params)

    def ex_create_reservation(self, sku):
        """
        Creates new package reservation for authenticated account.

        :param: sku: The sku code of product pricing plan. (required)
        :type:  sku: ``str``

        :rtype: ``dict``
        """
        data = {"sku": sku}
        return self._create_resource("reservation", data)

    def ex_list_reservations(self, product_category=None):
        """
        Retrieves all reservations associated with the authenticated account.
        All date & times are in UTC.

        :param: product_category: The product category.
        :type   product_category: ``str``

        :rtype: ``list`` of ``dict``
        """
        params = {"productCategory": product_category}
        return self._retrieve("reservation", params)

    def ex_edit_reservation_auto_renew_enable(self, reservation_id):
        """
        Enable auto-renewal for unexpired reservation by reservation id.

        :param: reservation_id: The reservation's ID.
        :type   reservation_id: ``str``

        :rtype: ``dict``
        """
        return self._edit_resource_by_id(
            "reservation", reservation_id, "/actions/auto-renew/enable"
        )

    def ex_edit_reservation_auto_renew_disable(self, reservation_id, reason):
        """
        Disable auto-renewal for reservation by reservation id.

        :param: reservation_id: The reservation's ID.
        :type   reservation_id: ``str``

        :param: reason: Reason for the disable
        :type   reason: ``str``

        :rtype: ``dict``
        """
        data = {"autoRenewDisableReason": reason}
        return self._edit_resource_by_id(
            "reservation", reservation_id, "/actions/auto-renew/disable", data=data
        )

    def ex_edit_reservation_convert(self, reservation_id, sku):
        """
        Convert reservation pricing model by reservation id.

        :param: reservation_id: The reservation's ID.
        :type   reservation_id: ``str``

        :param: sku: The sku code of product pricing plan.
        :type   sku: ``str``

        :rtype: ``dict``
        """
        data = {"sku": sku}
        return self._edit_resource_by_id(
            "reservation", reservation_id, "/actions/convert", data=data
        )

    def ex_create_rancher_cluster(
        self,
        location,
        name=None,
        description=None,
        node_pools=None,
        configuration=None,
        workload_configuration=None,
    ):
        """
        Create a Rancher Server Deployment asdescribed in Rancher Docs
        Architecture. Rancher Server allows the creation, import and
        management of multiple Downstream User Kubernetes Clusters.
        This is not a Downstream User Cluster.

        :param: location: Deployment location. Cannot be changed
                          once a cluster is created. (required)
        :type:  location: ``str``

        :param: name: Cluster name. This field is autogenerated
                      if not provided.
        :type:  name: ``str``

        :param: description: Cluster description.
        :type:  description: ``str``

        :param: nodePools: The node pools associated with the cluster.
        :type:  nodePools: ``list`` of ``dict``

        :param: configuration: Rancher configuration parameters.
        :type:  configuration: ``dict``

        :param: workload_configuration: Rancher configuration parameters.
        :type:  workload_configuration: ``dict``

        :rtype: ``dict``
        """
        data = {
            "location": location,
            "name": name,
            "description": description,
            "nodePools": node_pools,
            "configuration": configuration,
            "workloadConfiguration": workload_configuration,
        }
        return self._create_resource("cluster", data)

    def ex_list_rancher_clusters(self):
        """
        List all clusters owned by account.

        :rtype: ``list`` of ``dict``
        """
        return self._list_resources("cluster")

    def ex_delete_rancher_cluster_by_id(self, cluster_id):
        """
        Delete an existing cluster.

        :param: cluster_id: The Cluster identifier. (required)
        :type   cluster_id: ``str``

        :return: True on success
        :rtype: ``bool``
        """
        return self._delete_resource("cluster", cluster_id)

    def _to_key_pair(self, data):
        extra = {
            "id": data.get("id"),
            "default": data.get("default"),
            "createdOn": data.get("createdOn"),
            "lastUpdatedOn": data.get("lastUpdatedOn"),
        }
        return KeyPair(
            name=data.get("name"),
            fingerprint=data.get("fingerprint"),
            public_key=data.get("key"),
            private_key=None,
            driver=self,
            extra=extra,
        )

    def _to_tag(self, data):
        return PnapBmcTag(
            id=data.get("id"),
            name=data.get("name"),
            is_billing_tag=data.get("isBillingTag"),
            description=data.get("description"),
            values=data.get("values"),
            resource_assignments=data.get("resourceAssignments"),
            created_by=data.get("createdBy"),
        )

    def _to_ip_block(self, data):
        return PnapBmcIpBlock(
            id=data.get("id"),
            location=data.get("location"),
            cidr_block_size=data.get("cidrBlockSize"),
            cidr=data.get("cidr"),
            status=data.get("status"),
            assigned_resource_id=data.get("assignedResourceId"),
            assigned_resource_type=data.get("assignedResourceType"),
            description=data.get("description"),
            tags=data.get("tags"),
            is_bring_your_own=data.get("isBringYourOwn"),
            created_on=data.get("createdOn"),
        )

    def _to_private_network(self, data):
        return PnapBmcPrivateNetwork(
            id=data.get("id"),
            name=data.get("name"),
            description=data.get("description"),
            vlan_id=data.get("vlanId"),
            private_network_type=data.get("type"),
            location=data.get("location"),
            location_default=data.get("locationDefault"),
            cidr=data.get("cidr"),
            memberships=data.get("memberships"),
            created_on=data.get("createdOn"),
        )

    def _to_public_network(self, data):
        return PnapBmcPublicNetwork(
            id=data.get("id"),
            name=data.get("name"),
            description=data.get("description"),
            vlan_id=data.get("vlanId"),
            memberships=data.get("memberships"),
            location=data.get("location"),
            ip_blocks=data.get("ipBlocks"),
            created_on=data.get("createdOn"),
        )

    def _to_node(self, data):
        """Convert node in Node instances"""

        state = NODE_STATE_MAP.get(data.get("status"))
        public_ips = []
        [public_ips.append(pup) for pup in data.get("publicIpAddresses", [])]
        private_ips = []
        [private_ips.append(pip) for pip in data.get("privateIpAddresses", [])]
        size = data.get("type")
        image = data.get("os")
        extra = {
            "description": data.get("description"),
            "location": data.get("location"),
            "cpu": data.get("cpu"),
            "cpuCount": data.get("cpuCount"),
            "coresPerCpu": data.get("coresPerCpu"),
            "cpuFrequency": data.get("cpuFrequency"),
            "ram": data.get("ram"),
            "storage": data.get("storage"),
            "reservationId": data.get("reservationId"),
            "pricingModel": data.get("pricingModel"),
            "password": data.get("password"),
            "networkType": data.get("networkType"),
            "clusterId": data.get("clusterId"),
            "tags": data.get("tags"),
            "provisionedOn": data.get("provisionedOn"),
            "osConfiguration": data.get("osConfiguration"),
            "networkConfiguration": data.get("networkConfiguration"),
        }
        return Node(
            id=data.get("id"),
            name=data.get("hostname"),
            state=state,
            public_ips=public_ips,
            private_ips=private_ips,
            driver=self,
            size=size,
            image=image,
            extra=extra,
        )

    def _node_action(self, node, action, data=None):
        data = json.dumps(self._remove_empty_elements(data))
        res = self.connection.request(
            API_ENDPOINTS["NODE"] + node.id + "/actions/%s" % (action),
            method="POST",
            data=data,
        )
        return res.status in VALID_RESPONSE_CODES

    def _create_resource(self, resource_name, data):
        has_own_class = getattr(self, "_to_" + resource_name, None)
        data = json.dumps(self._remove_empty_elements(data))
        response = self.connection.request(
            API_ENDPOINTS[resource_name.upper()], data=data, method="POST"
        ).object
        if has_own_class:
            return getattr(self, "_to_" + resource_name)(response)
        else:
            return response

    def _list_resources(self, resource_name):
        has_own_class = getattr(self, "_to_" + resource_name, None)
        response = self.connection.request(API_ENDPOINTS[resource_name.upper()]).object
        if has_own_class:
            return list(map(getattr(self, "_to_" + resource_name), response))
        else:
            return response

    def _get_resource(self, resource_name, identifier):
        if resource_name == "node":
            resource_key = "hostname"
        elif resource_name == "ip_block":
            resource_key = "id"
        else:
            resource_key = "name"
        response = self.connection.request(API_ENDPOINTS[resource_name.upper()]).object
        for item in response:
            if item[resource_key] == identifier:
                return getattr(self, "_to_" + resource_name)(item)

    def _edit_resource(self, resource_name, resource, data, method="PATCH"):
        if resource_name == "key_pair":
            resource_id = resource.extra["id"]
        else:
            resource_id = resource.id

        data = json.dumps(self._remove_empty_elements(data))
        response = self.connection.request(
            API_ENDPOINTS[resource_name.upper()] + resource_id, data=data, method=method
        ).object
        return getattr(self, "_to_" + resource_name)(response)

    def _edit_resource_by_id(
        self,
        resource_name,
        resource_id,
        end_of_url,
        sub_resource_id="",
        data=None,
        method="POST",
        raw_response=False,
        check_class=True,
    ):
        has_own_class = getattr(self, "_to_" + resource_name, None)
        data = json.dumps(self._remove_empty_elements(data))
        response = self.connection.request(
            API_ENDPOINTS[resource_name.upper()]
            + resource_id
            + end_of_url
            + sub_resource_id,
            data=data,
            method=method,
        )
        if not raw_response:
            response = response.object
        if has_own_class and check_class:
            return getattr(self, "_to_" + resource_name)(response)
        else:
            return response

    def _delete_resource(self, resource_name, resource):
        if resource_name == "key_pair":
            resource_id = resource.extra["id"]
        elif isinstance(resource, PNAP_BMC_TYPES.get(resource_name, bool)):
            resource_id = resource.id
        else:
            resource_id = resource

        res = self.connection.request(
            API_ENDPOINTS[resource_name.upper()] + resource_id, method="DELETE"
        )
        return res.status in VALID_RESPONSE_CODES

    def _retrieve(self, resource_name, params=None, method="GET"):
        params = self._remove_empty_elements(params)
        return self.connection.request(
            API_ENDPOINTS[resource_name.upper()], params, method
        ).object

    def _remove_empty_elements(self, d):
        """recursively remove empty elements from a dictionary"""

        def empty(x):
            return x is None or x == {} or x == [] or x == ""

        if not isinstance(d, (dict, list)):
            return d
        elif isinstance(d, list):
            return [
                v for v in (self._remove_empty_elements(v) for v in d) if not empty(v)
            ]
        else:
            return {
                k: v
                for k, v in ((k, self._remove_empty_elements(v)) for k, v in d.items())
                if not empty(v)
            }
