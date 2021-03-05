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

import sys
import unittest
from libcloud.utils.py3 import httplib

from libcloud.compute.types import NodeState
from libcloud.compute.drivers.pnap_bmc import PnapBmcNodeDriver
from libcloud.compute.drivers.pnap_bmc import VALID_RESPONSE_CODES

from libcloud.test import MockHttp
from libcloud.test.compute import TestCaseMixin
from libcloud.test.file_fixtures import ComputeFileFixtures


class PnapBmcTest(unittest.TestCase, TestCaseMixin):
    PnapBmcNodeDriver.connectionCls._get_auth_token = lambda x: x
    PnapBmcNodeDriver.connectionCls.token = 'token'

    def setUp(self):
        PnapBmcNodeDriver.connectionCls.conn_class = PnapBmcMockHttp
        self.driver = PnapBmcNodeDriver('clientId', 'clientSecret')

    def test_list_locations_response(self):
        locations = self.driver.list_locations()
        self.assertEqual(len(locations), 4)

    def test_list_images_response(self):
        images = self.driver.list_images()
        self.assertEqual(len(images), 4)

    def test_list_sizes_response(self):
        sizes = self.driver.list_sizes()
        self.assertEqual(len(sizes), 20)

    def test_http_status_ok_in_valid_responses(self):
        self.assertTrue(httplib.OK in VALID_RESPONSE_CODES)

    def test_http_status_accepted_in_valid_responses(self):
        self.assertTrue(httplib.ACCEPTED in VALID_RESPONSE_CODES)

    def test_list_nodes_response(self):
        nodes = self.driver.list_nodes()
        node = nodes[0]
        self.assertTrue(isinstance(nodes, list))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(node.id, '5f739c1xxx0f4e59dxxx52dc')
        self.assertEqual(node.name, 'server-red')
        self.assertEqual(node.state, NodeState.RUNNING)
        self.assertTrue('10.0.0.11' in node.private_ips)
        self.assertTrue('10.111.14.2' in node.public_ips)
        self.assertTrue('10.111.14.3' in node.public_ips)

    def test_reboot_node(self):
        node = self.driver.list_nodes()[0]
        response = self.driver.reboot_node(node)
        self.assertTrue(response)

    def test_start_node(self):
        node = self.driver.list_nodes()[0]
        response = self.driver.start_node(node)
        self.assertTrue(response)

    def test_stop_node(self):
        node = self.driver.list_nodes()[0]
        response = self.driver.stop_node(node)
        self.assertTrue(response)

    def test_destroy_node(self):
        node = self.driver.list_nodes()[0]
        response = self.driver.destroy_node(node)
        self.assertTrue(response)

    def test_create_node_response(self):
        test_size = self.driver.list_sizes()[0]
        test_image = self.driver.list_images()[0]
        test_location = self.driver.list_locations()[0]
        created_node = self.driver.create_node('node-name',
                                               test_size,
                                               test_image,
                                               test_location)
        self.assertEqual(created_node.id, "5f73xxxe6a0f4e59xxx152dc")
        self.assertEqual(created_node.state, NodeState.PENDING)

    def test_list_keypairs(self):
        keys = self.driver.list_key_pairs()
        self.assertEqual(2, len(keys))
        self.assertFalse(keys[0].extra['default'])
        self.assertEqual('123', keys[0].extra['id'])
        self.assertEqual('testkey1', keys[0].name)
        self.assertEqual('RRfGJ32A2EKUHxf6fEgnr4Rcp4rkNO8Gn5rtqu4E',
                         keys[0].fingerprint)
        self.assertTrue(keys[0].public_key.startswith('ssh-rsa'))

    def test_get_key_pair(self):
        key = self.driver.get_key_pair('testkey2')
        self.assertTrue(key.extra['default'])
        self.assertEqual('456', key.extra['id'])
        self.assertEqual('testkey2', key.name)
        self.assertEqual('j6or1TMmFKhGK6Z5dFoj9leNqbDEqsfUjmbJ8hwv',
                         key.fingerprint)
        self.assertTrue(key.public_key.startswith('ssh-rsa'))

    def test_import_key_pair_from_string(self):
        key = self.driver.import_key_pair_from_string(
            'testkey3',
            'ssh-rsa AAAADAQABAAABAQCeFQa32lIyVOyjph6e3e8')
        self.assertTrue(key.extra['default'])
        self.assertEqual('224', key.extra['id'])
        self.assertEqual('testkey3', key.name)
        self.assertEqual('RRfBJ32A2EKUHxf6fEgnr4Rcp4rkNO8G++rtqu4E',
                         key.fingerprint)
        self.assertTrue(key.public_key.startswith('ssh-rsa'))

    def test_delete_key_pair(self):
        key = self.driver.get_key_pair('testkey1')
        response = self.driver.delete_key_pair(key)
        self.assertTrue(response)


class PnapBmcMockHttp(MockHttp):
    fixtures = ComputeFileFixtures('pnap_bmc')

    def _bmc_v1_servers(self, method, url, body, headers):
        if method == 'GET':
            body = self.fixtures.load('list_nodes.json')
            return (httplib.ACCEPTED, body, {},
                    httplib.responses[httplib.ACCEPTED])
        else:
            body = self.fixtures.load('create_node.json')
            return (httplib.ACCEPTED, body, {},
                    httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_5f739c1xxx0f4e59dxxx52dc_actions_shutdown(
                                     self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_5f739c1xxx0f4e59dxxx52dc_actions_power_on(
                                     self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_5f739c1xxx0f4e59dxxx52dc_actions_reboot(
                                   self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_5f739c1xxx0f4e59dxxx52dc(
                    self, method, url, body, headers):
        assert method == 'DELETE'
        return (httplib.OK, "", {}, 'httplib.responses[httplib.OK]')

    def _bmc_v1_ssh_keys(self, method, url, body, headers):
        if method == 'GET':
            body = self.fixtures.load('list_key_pairs.json')
        else:
            body = self.fixtures.load('import_key_pair.json')
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _bmc_v1_ssh_keys_123(self, method, url, body, headers):
        assert method == 'DELETE'
        return (httplib.OK, "", {}, 'httplib.responses[httplib.OK]')


if __name__ == '__main__':
    sys.exit(unittest.main())
