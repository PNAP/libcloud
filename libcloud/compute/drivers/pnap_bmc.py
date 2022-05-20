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
from base64 import standard_b64encode

from libcloud.utils.py3 import httplib
from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import (NodeState, InvalidCredsError)
from libcloud.compute.base import (Node, NodeDriver, NodeImage, NodeSize,
                                   NodeLocation, KeyPair)


AUTH_API = 'https://auth.phoenixnap.com/auth/realms/BMC/protocol/openid-connect/token' # noqa
PATH = '/bmc/v1/servers/'
SSH_PATH = '/bmc/v1/ssh-keys/'
NODE_STATE_MAP = {
    'creating': NodeState.PENDING,
    'rebooting': NodeState.PENDING,
    'resetting': NodeState.PENDING,
    'powered-on': NodeState.RUNNING,
    'powered-off': NodeState.STOPPED,
    'error': NodeState.ERROR,
}

VALID_RESPONSE_CODES = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                        httplib.NO_CONTENT]


class PnapBmcResponse(JsonResponse):
    """
    PNAP_BMC API Response
    """

    def parse_error(self):
        if self.status == httplib.UNAUTHORIZED:
            raise InvalidCredsError('Authorization Failed')
        if self.status == httplib.NOT_FOUND:
            raise Exception("The resource you are looking for is not found.")
        if self.status != httplib.OK:
            body = self.parse_body()
            err = 'Missing an error message'
            if 'message' in body:
                ve = str(body.get('validationErrors') or '')
                err = '%s %s(code:%s)' % (body.get('message'), ve, self.status)
            raise Exception(err)

    def success(self):
        return self.status in VALID_RESPONSE_CODES


class PnapBmcConnection(ConnectionUserAndKey):
    """
    Connection class for the PNAP_BMC driver.
    """

    host = 'api.phoenixnap.com'
    responseCls = PnapBmcResponse

    def add_default_headers(self, headers):
        self._get_auth_token()
        headers.update({'Content-Type': 'application/json'})
        headers.update({'Authorization': 'Bearer %s' % self.token})
        return headers

    def _get_auth_token(self):
        body = {'grant_type': 'client_credentials'}
        self.connection.request(method='POST', url=AUTH_API, body=body,
                                headers=self._get_auth_headers())
        response = self.connection.getresponse()
        try:
            self.token = response.json()['access_token']
        except KeyError:
            raise InvalidCredsError() from None

    def _get_auth_headers(self):
        auth_data = "%s:%s" % (self.user_id, self.key)
        basic_auth = standard_b64encode(auth_data.encode("utf-8"))
        return {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic %s' % basic_auth.decode("utf-8")
        }


class PnapBmcNodeDriver(NodeDriver):
    """
    PNAP_BMC NodeDriver
    >>> from libcloud.compute.providers import get_driver
    >>> driver = get_driver(Provider.PNAP_BMC)
    >>> conn = driver('Client ID','Client Secret')
    >>> conn.list_nodes()
    """

    type = Provider.PNAP_BMC
    name = 'PNAP_BMC'
    website = 'https://www.phoenixnap.com/'
    connectionCls = PnapBmcConnection

    def list_locations(self):
        """
        List available locations.

        :rtype: ``list`` of :class:`NodeLocation`
        """
        return [
            NodeLocation('PHX', 'PHOENIX', 'US', self),
            NodeLocation('ASH', 'ASHBURN', 'US', self),
            NodeLocation('NLD', 'AMSTERDAM', 'NLD', self),
            NodeLocation('SGP', 'SINGAPORE', 'SGP', self),
            NodeLocation('CHI', 'CHICAGO', 'CHI', self),
            NodeLocation('SEA', 'SEATTLE', 'SEA', self),
            NodeLocation('AUS', 'AUSTIN', 'AUS', self),
        ]

    def list_images(self, location=None):
        """
        List available operating systems.

        :rtype: ``list`` of :class:`NodeSize`
        """
        return [
            NodeImage('ubuntu/bionic', 'ubuntu/bionic', self),
            NodeImage('ubuntu/focal', 'ubuntu/focal', self),
            NodeImage('centos/centos7', 'centos/centos7', self),
            NodeImage('windows/srv2019std', 'windows/srv2019std', self),
            NodeImage('windows/srv2019dc', 'windows/srv2019dc', self),
            NodeImage('esxi/esxi70u2', 'esxi/esxi70u2', self),
            NodeImage('debian/bullseye', 'debian/bullseye', self),
            NodeImage('proxmox/bullseye', 'proxmox/bullseye', self),
        ]

    def list_sizes(self, location=None):
        """
        List available server types.

        :rtype: ``list`` of :class:`NodeImage`
        """
        sizes = []
        url = 'billing/v1/products?productCategory=SERVER'
        servers = self.connection.request(url).object
        for ser in servers:
            sizes.append(NodeSize(ser['productCode'], ser['productCode'],
                                  ser["metadata"]["ramInGb"] * 1000,
                                  None, None, None, self
                                  )
                         )
        return sizes

    def list_nodes(self):
        """
        List all your existing compute nodes.

        :rtype: ``list`` of :class:`Node`
        """
        result = self.connection.request(PATH).object
        nodes = [self._to_node(value) for value in result]
        return nodes

    def reboot_node(self, node):
        """
        Reboot a node.
        """
        return self._action(node, 'reboot')

    def start_node(self, node):
        """
        Start a node.
        """
        return self._action(node, 'power-on')

    def stop_node(self, node):
        """
        Stop a specific node.
        """
        return self._action(node, 'shutdown')

    def destroy_node(self, node, ex_delete_ip_blocks=True):
        """
        Delete a specific node.
        This is an irreversible action, and once performed,
        no data can be retrieved.

        :keyword ex_delete_ip_blocks: Determines whether the IP blocks
                                      assigned to the server should be
                                      deleted or not.
        :type    ex_delete_ip_blocks: ``bool``
        """
        data = {
            "deleteIpBlocks": ex_delete_ip_blocks
        }
        return self._action(node, 'deprovision', data)

    def ex_power_off_node(self, node):
        """
        Power off a specific node
        (which is equivalent to cutting off electricity from the server).
        We strongly advise you to use the stop_node in order to minimize
        any possible data loss or corruption.
        """
        return self._action(node, 'power-off')

    def create_node(self, name, size, image, location,
                    ex_ip_blocks_configuration_type=None,
                    ex_ip_blocks_id=None,
                    ex_management_access_allowed_ips=None,
                    ex_gateway_address=None,
                    ex_private_network_configuration_type=None,
                    ex_private_networks=None,
                    ex_public_networks=None,
                    ex_tags=None,
                    ex_description=None, ex_ssh_keys=None,
                    ex_install_default_ssh_keys=True,
                    ex_ssh_key_ids=None, ex_reservation_id=None,
                    ex_pricing_model="HOURLY",
                    ex_network_type="PUBLIC_AND_PRIVATE",
                    ex_rdp_allowed_ips=None):
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
        :type    ex_ssh_keys: ``str``

        :keyword ex_ssh_key_ids: A list of SSH Key IDs that will be installed
                                 on the server in addition to any ssh keys
                                 specified in this request.
        :type    ex_ssh_key_ids: ``list``

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
        :type    ex_rdp_allowed_ips: ``list``

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
            "installDefaultSshKeys": ex_install_default_ssh_keys,
            "reservationId": ex_reservation_id,
            "pricingModel": ex_pricing_model,
            "networkType": ex_network_type,
            "networkConfiguration": {
                "gatewayAddress": ex_gateway_address,
                "privateNetworkConfiguration": {
                    "configurationType": ex_private_network_configuration_type,
                    "privateNetworks": ex_private_networks
                },
                "ipBlocksConfiguration": {
                    "configurationType": ex_ip_blocks_configuration_type,
                    "ipBlocks": ex_ip_blocks_id
                },
                "publicNetworkConfiguration": {
                    "publicNetworks": ex_public_networks
                }
             },
            "osConfiguration": {
                "managementAccessAllowedIps": ex_management_access_allowed_ips,
                "windows": {
                    "rdpAllowedIps": ex_rdp_allowed_ips
                }
            },
            "tags": ex_tags,

        }
        data = json.dumps(self._remove_empty_elements(data))
        result = self.connection.request(PATH, data=data, method='POST').object
        node = self._to_node(result)
        return node

    def list_key_pairs(self):
        """
        List all the available SSH keys.

        :return: Available SSH keys.
        :rtype: ``list`` of :class:`SSHKey`
        """
        res = self.connection.request(SSH_PATH).object
        return list(map(self._to_key_pair, res))

    def get_key_pair(self, name):
        """
        Retrieve a single key pair.

        :param name: Name of the key pair to retrieve.
        :type name: ``str``

        :rtype: :class:`.KeyPair`
        """
        return self._get_ssh_key_from_name(name)

    def import_key_pair_from_string(self, name, key_material, default=False):
        """
        Import a new public key from string.

        :param name: Key pair name.
        :type name: ``str``

        :param key_material: Public key material.
        :type key_material: ``str``

        :param default: Keys marked as default are always included
                        on server creation and reset unless
                        toggled off in creation/reset request.
        :type default: ``bool``

        :return: Imported key pair object.
        :rtype: :class:`.KeyPair`
        """
        data = {
            "name": name,
            "key": key_material,
            "default": default
        }
        data = json.dumps(data)
        res = self.connection.request(SSH_PATH,
                                      data=data,
                                      method='POST').object
        return self._to_key_pair(res)

    def import_key_pair_from_file(self, name, key_file_path, default=False):
        """
        Import a new public key from file.

        :param name: Key pair name.
        :type name: ``str``

        :param key_file_path: Path to the public key file.
        :type key_file_path: ``str``

        :param default: Keys marked as default are always included
                        on server creation and reset unless
                        toggled off in creation/reset request.
        :type default: ``bool``

        :return: Imported key pair object.
        :rtype: :class:`.KeyPair`
        """
        key_file_path = os.path.expanduser(key_file_path)

        with open(key_file_path, 'r') as fp:
            key_material = fp.read().strip()

        return self.import_key_pair_from_string(name=name,
                                                key_material=key_material,
                                                default=default)

    def delete_key_pair(self, key_pair):
        """
        Delete an existing SSH key.
        :param: key_pair: SSH key (required)
        :type   key_pair: :class:`KeyPair`

        :return: True on success
        :rtype: ``bool``
        """
        res = self.connection.request(SSH_PATH + key_pair.extra["id"],
                                      method='DELETE')
        return res.status in VALID_RESPONSE_CODES

    def ex_edit_key_pair(self, key_pair, name=None, default=None):
        """
        Edit an existing SSH key.
        :param: key_pair: SSH key (required)
        :type:  key_pair: :class:`KeyPair`

        :param: name: New SSH Key name that can represent
                      the key as an alternative to it's ID.
        :type: ``str``

        :param: default: Keys marked as default are always included
                         on server creation and reset unless toggled off
                         in creation/reset request.
        :type: ``bool``
        """
        if name is None:
            name = key_pair.name
        if default is None:
            default = key_pair.extra['default']
        data = {
            "name": name,
            "default": default
        }
        data = json.dumps(data)
        res = self.connection.request(SSH_PATH + key_pair.extra["id"],
                                      data=data,
                                      method='PUT').object
        return self._to_key_pair(res)

    def _get_ssh_key_from_name(self, name):
        res = self.connection.request(SSH_PATH).object
        for key in res:
            if key['name'] == name:
                return self._to_key_pair(key)

    def _to_key_pair(self, data):
        extra = {'id': data['id'],
                 'default': data['default'],
                 'createdOn': data['createdOn'],
                 'lastUpdatedOn': data['lastUpdatedOn']}
        key_pair = KeyPair(name=data['name'],
                           fingerprint=data['fingerprint'],
                           public_key=data['key'],
                           private_key=None,
                           driver=self,
                           extra=extra)
        return key_pair

    def _action(self, node, action, data=None):
        data = json.dumps(data)
        res = self.connection.request(PATH + node.id + '/actions/%s'
                                      % (action), method='POST', data=data)
        return res.status in VALID_RESPONSE_CODES

    def _to_node(self, data):
        """Convert node in Node instances
        """

        state = NODE_STATE_MAP.get(data.get('status'))
        public_ips = []
        [public_ips.append(pup) for pup in data.get('publicIpAddresses', [])]
        private_ips = []
        [private_ips.append(pip) for pip in data.get('privateIpAddresses', [])]
        size = data.get('type')
        image = data.get('os')
        extra = {
            'description': data.get('description'),
            'location': data.get('location'),
            'cpu': data.get('cpu'),
            'cpuCount': data.get('cpuCount'),
            'coresPerCpu': data.get('coresPerCpu'),
            'cpuFrequency': data.get('cpuFrequency'),
            'ram': data.get('ram'),
            'storage': data.get('storage'),
            'reservationId': data.get('reservationId'),
            'pricingModel': data.get('pricingModel'),
            'password': data.get('password'),
            'networkType': data.get('networkType'),
            'clusterId': data.get('clusterId'),
            'tags': data.get('tags'),
            'provisionedOn': data.get('provisionedOn'),
            'osConfiguration': data.get('osConfiguration'),
            'networkConfiguration': data.get('networkConfiguration')
        }
        node = Node(id=data.get('id'), name=data.get('hostname'), state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self, size=size, image=image, extra=extra)
        return node

    def _remove_empty_elements(self, d):
        """recursively remove empty elements from a dictionary"""

        def empty(x):
            return x is None or x == {} or x == [] or x == ''

        if not isinstance(d, (dict, list)):
            return d
        elif isinstance(d, list):
            return [v for v in (self._remove_empty_elements(v)
                    for v in d) if not empty(v)]
        else:
            return {k: v for k, v in ((k, self._remove_empty_elements(v))
                    for k, v in d.items()) if not empty(v)}
