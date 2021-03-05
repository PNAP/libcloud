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
from base64 import standard_b64encode

from libcloud.utils.py3 import httplib
from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import (NodeState, InvalidCredsError)
from libcloud.compute.base import (Node, NodeDriver, NodeImage, NodeSize,
                                   NodeLocation, KeyPair)

PNAP_BMC_SERVER_TYPES = [
    {
        'id': 's1.c1.small',
        'name': 's1.c1.small',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 's1.c1.medium',
        'name': 's1.c1.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 's1.c2.medium',
        'name': 's1.c2.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 's1.c2.large',
        'name': 's1.c2.large',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c1.small',
        'name': 'd1.c1.small',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c2.small',
        'name': 'd1.c2.small',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c3.small',
        'name': 'd1.c3.small',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c4.small',
        'name': 'd1.c4.small',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c1.medium',
        'name': 'd1.c1.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c2.medium',
        'name': 'd1.c2.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c3.medium',
        'name': 'd1.c3.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c4.medium',
        'name': 'd1.c4.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c1.large',
        'name': 'd1.c1.large',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c2.large',
        'name': 'd1.c2.large',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c3.large',
        'name': 'd1.c3.large',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.c4.large',
        'name': 'd1.c4.large',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.m1.medium',
        'name': 'd1.m1.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.m2.medium',
        'name': 'd1.m2.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.m3.medium',
        'name': 'd1.m3.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
    {
        'id': 'd1.m4.medium',
        'name': 'd1.m4.medium',
        'ram': 'N/A',
        'disk': 'N/A',
        'cpu': 'N/A',
        'price': 'N/A',
    },
]

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
        ]

    def list_images(self, location=None):
        """
        List available operating systems.

        :rtype: ``list`` of :class:`NodeSize`
        """
        return [
            NodeImage('ubuntu/bionic', 'ubuntu/bionic', self),
            NodeImage('centos/centos7', 'centos/centos7', self),
            NodeImage('windows/srv2019std', 'windows/srv2019std', self),
            NodeImage('windows/srv2019dc', 'windows/srv2019dc', self),
        ]

    def list_sizes(self, location=None):
        """
        List available server types.

        :rtype: ``list`` of :class:`NodeImage`
        """
        sizes = []
        for server in PNAP_BMC_SERVER_TYPES:
            sizes.append(NodeSize(server['id'], server['name'],
                                  server['ram'], server['disk'],
                                  server['cpu'], server['price'], self
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

    def destroy_node(self, node):
        """
        Delete a specific node.
        This is an irreversible action, and once performed,
        no data can be retrieved.
        """
        return self._action(node, 'destroy')

    def ex_power_off_node(self, node):
        """
        Power off a specific node
        (which is equivalent to cutting off electricity from the server).
        We strongly advise you to use the stop_node in order to minimize
        any possible data loss or corruption.
        """
        return self._action(node, 'power-off')

    def ex_reset_node(self, node, ex_ssh_keys=None,
                      ex_installdefault_sshkeys=True,
                      ex_sshkey_ids=None, ex_rdp_allowed_ips=None):
        """
        Reset a specific node. At least one SSH public key is required.
        All data currently on the server will be wiped, and the OS will
        be re-installed. This is an irreversible action, and once performed,
        no existing data may be retrieved.

        :keyword ex_installdefault_sshkeys: Whether or not to install ssh keys
                                            marked as default in addition
                                            to any ssh keys specified
                                            in this request.
        :type    ex_installdefault_sshkeys: ``bool``

        :keyword ex_ssh_keys: A list of SSH Keys that will be
                              installed on the server.
        :type    ex_ssh_keys: ``str``

        :keyword ex_sshkey_ids: A list of SSH Key IDs that will be installed
                                on the server in addition to any ssh keys
                                specified in this request.
        :type    ex_sshkey_ids: ``str``

        :keyword ex_rdp_allowed_ips: List of IPs allowed for RDP access to
                                     Windows OS. Supported in single IP, CIDR
                                     and range format. When undefined, RDP is
                                     disabled. To allow RDP access from any IP
                                     use 0.0.0.0/0
        :type    ex_rdp_allowed_ips: ``str``
        """
        reset_params = {
            "sshKeys": [ex_ssh_keys],
            "installDefaultSshKeys": ex_installdefault_sshkeys,
            "osConfiguration": {
                "windows": {
                    "rdpAllowedIps": [ex_rdp_allowed_ips]
                }
            }
        }
        if ex_sshkey_ids is not None:
            reset_params["sshKeyIds"] = [ex_sshkey_ids]
        return self._action(node, 'reset', reset_params=reset_params)

    def create_node(self, name, size, image, location,
                    ex_description=None, ex_ssh_keys=None,
                    ex_installdefault_sshkeys=True,
                    ex_sshkey_ids=None, ex_reservation_id=None,
                    ex_pricing_model="HOURLY",
                    ex_network_type="PUBLIC_AND_PRIVATE",
                    ex_rdp_allowed_ips=None):
        """
        Create a node.

        :keyword ex_description: Description of server.
        :type    ex_description: ``str``

        :keyword ex_installdefault_sshkeys: Whether or not to install ssh keys
                                            marked as default in addition
                                            to any ssh keys specified
                                            in this request.
        :type    ex_installdefault_sshkeys: ``bool``

        :keyword ex_ssh_keys: A list of SSH Keys that will be
                              installed on the server.
        :type    ex_ssh_keys: ``str``

        :keyword ex_sshkey_ids: A list of SSH Key IDs that will be installed
                                on the server in addition to any ssh keys
                                specified in this request.
        :type    ex_sshkey_ids: ``str``

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
        :type    ex_rdp_allowed_ips: ``str``

        :return: The newly created node.
        :rtype: :class:`Node`
        """
        data = {
            "hostname": name,
            "type": size.id,
            "os": image.id,
            "location": location.id,
            "description": ex_description,
            "sshKeys": [ex_ssh_keys],
            "installDefaultSshKeys": ex_installdefault_sshkeys,
            "reservationId": ex_reservation_id,
            "pricingModel": ex_pricing_model,
            "networkType": ex_network_type,
            "osConfiguration": {
                "windows": {
                    "rdpAllowedIps": [ex_rdp_allowed_ips]
                }
            }
        }
        if ex_sshkey_ids is not None:
            data["sshKeyIds"] = [ex_sshkey_ids]
        data = json.dumps(data)
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

    def import_key_pair_from_string(self, name, key_material):
        """
        Import a new public key from string.

        :param name: Key pair name.
        :type name: ``str``

        :param key_material: Public key material.
        :type key_material: ``str``

        :return: Imported key pair object.
        :rtype: :class:`.KeyPair`
        """
        data = {
            "name": name,
            "key": key_material,
            "default": False
        }
        data = json.dumps(data)
        res = self.connection.request(SSH_PATH,
                                      data=data,
                                      method='POST').object
        return self._to_key_pair(res)

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

    def ex_edit_key_pair(self, key_pair, name=None, default=False):
        """
        Edit an existing SSH key.
        :param: key_pair: SSH key (required)
        :type:  key_pair: :class:`KeyPair`

        :param: name: SSH Key name that can represent the key
                      as an alternative to it's ID.
        :type: ``str``

        :param: default: Keys marked as default are always included
                         on server creation and reset unless toggled off
                         in creation/reset request.
        :type: ``bool``
        """
        if name is None:
            name = key_pair.name
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
        extra = {"id": data["id"],
                 "default": data["default"],
                 "createdOn": data["createdOn"],
                 "lastUpdatedOn": data["lastUpdatedOn"]}
        key_pair = KeyPair(name=data['name'],
                           fingerprint=data['fingerprint'],
                           public_key=data['key'],
                           private_key=None,
                           driver=self,
                           extra=extra)
        return key_pair

    def _action(self, node, action, reset_params=None):
        if action == 'destroy':
            res = self.connection.request(PATH + node.id, method='DELETE')
        elif action == 'reset':
            data = json.dumps(reset_params)
            res = self.connection.request(PATH + node.id + '/actions/%s'
                                          % (action), method='POST', data=data)
        else:
            res = self.connection.request(PATH + node.id + '/actions/%s'
                                          % (action), method='POST')
        return res.status in VALID_RESPONSE_CODES

    def _to_node(self, data):
        """Convert node in Node instances
        """

        state = NODE_STATE_MAP.get(data['status'])
        public_ips = []
        [public_ips.append(pup) for pup in data['publicIpAddresses']]
        private_ips = []
        [private_ips.append(pip) for pip in data['privateIpAddresses']]
        size = data['type']
        image = data['os']
        extra = {
            'description': data['description'],
            'location': data['location'],
            'cpu': data['cpu'],
            'cpuCount': data['cpuCount'],
            'coresPerCpu': data['coresPerCpu'],
            'cpuFrequency': data['cpuFrequency'],
            'ram': data['ram'],
            'storage': data['storage'],
            'reservationId': data['reservationId'],
            'pricingModel': data['pricingModel'],
            'password': data['password'],
            'networkType': data['networkType'],
        }
        node = Node(id=data['id'], name=data['hostname'], state=state,
                    public_ips=public_ips, private_ips=private_ips,
                    driver=self, size=size, image=image, extra=extra)
        return node
