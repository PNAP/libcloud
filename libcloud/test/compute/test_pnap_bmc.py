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
    PnapBmcNodeDriver.connectionCls.token = "token"

    def setUp(self):
        PnapBmcNodeDriver.connectionCls.conn_class = PnapBmcMockHttp
        self.driver = PnapBmcNodeDriver("clientId", "clientSecret")

    def test_list_locations_count(self):
        locations = self.driver.list_locations()
        self.assertEqual(len(locations), 7)

    def test_list_images_count(self):
        images = self.driver.list_images()
        self.assertEqual(len(images), 9)

    def test_list_sizes_response(self):
        sizes = self.driver.list_sizes()
        server = sizes[0]
        self.assertEqual(len(sizes), 3)
        self.assertTrue(isinstance(sizes, list))
        self.assertEqual(server.id, "d1.c1.large")
        self.assertEqual(server.ram, 256 * 1000)

    def test_list_sizes_location_AUS(self):
        sizes = self.driver.list_sizes("AUS")
        self.assertEqual(len(sizes), 1)

    def test_list_sizes_location_PHX(self):
        location = [i for i in self.driver.list_locations() if i.name == "PHOENIX"][0]
        sizes = self.driver.list_sizes(location)
        self.assertEqual(len(sizes), 3)

    def test_http_status_ok_in_valid_responses(self):
        self.assertTrue(httplib.OK in VALID_RESPONSE_CODES)

    def test_http_status_accepted_in_valid_responses(self):
        self.assertTrue(httplib.ACCEPTED in VALID_RESPONSE_CODES)

    def test_list_nodes_response(self):
        nodes = self.driver.list_nodes()
        node = nodes[0]
        self.assertTrue(isinstance(nodes, list))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(node.id, "123")
        self.assertEqual(node.name, "server-red")
        self.assertEqual(node.state, NodeState.RUNNING)
        self.assertTrue("10.0.0.11" in node.private_ips)
        self.assertTrue("10.111.14.2" in node.public_ips)
        self.assertTrue("10.111.14.3" in node.public_ips)

    def test_reboot_node(self):
        node = self.driver.list_nodes()[0]
        self.assertTrue(self.driver.reboot_node(node))

    def test_start_node(self):
        node = self.driver.list_nodes()[0]
        self.assertTrue(self.driver.start_node(node))

    def test_stop_node(self):
        node = self.driver.list_nodes()[0]
        self.assertTrue(self.driver.stop_node(node))

    def test_ex_power_off_node(self):
        node = self.driver.list_nodes()[0]
        self.assertTrue(self.driver.ex_power_off_node(node))

    def test_ex_edit_node(self):
        existing_node = self.driver.list_nodes()[0]
        node = self.driver.ex_edit_node(existing_node, "description_edit")
        self.assertEqual(node.id, "123")

    def test_destroy_node(self):
        node = self.driver.list_nodes()[0]
        self.assertTrue(self.driver.destroy_node(node))

    def test_create_node_response(self):
        test_size = self.driver.list_sizes()[0]
        test_image = self.driver.list_images()[0]
        test_location = self.driver.list_locations()[0]
        node = self.driver.create_node(
            "node-name", test_size, test_image, test_location
        )
        self.assertEqual(node.id, "123")
        self.assertEqual(node.state, NodeState.PENDING)

    def test_list_keypairs(self):
        keys = self.driver.list_key_pairs()
        self.assertEqual(2, len(keys))
        self.assertFalse(keys[0].extra["default"])
        self.assertEqual("123", keys[0].extra["id"])
        self.assertEqual("testkey1", keys[0].name)
        self.assertEqual(
            "RRfGJ32A2EKUHxf6fEgnr4Rcp4rkNO8Gn5rtqu4E", keys[0].fingerprint
        )
        self.assertTrue(keys[0].public_key.startswith("ssh-rsa"))

    def test_get_key_pair(self):
        key = self.driver.get_key_pair("testkey2")
        self.assertTrue(key.extra["default"])
        self.assertEqual("456", key.extra["id"])
        self.assertEqual("testkey2", key.name)
        self.assertEqual("j6or1TMmFKhGK6Z5dFoj9leNqbDEqsfUjmbJ8hwv", key.fingerprint)
        self.assertTrue(key.public_key.startswith("ssh-rsa"))

    def test_import_key_pair_from_string(self):
        key = self.driver.import_key_pair_from_string(
            "testkey3", "ssh-rsa AAAADAQABAAABAQCeFQa32lIyVOyjph6e3e8"
        )
        self.assertTrue(key.extra["default"])
        self.assertEqual("224", key.extra["id"])
        self.assertEqual("testkey3", key.name)
        self.assertEqual("RRfBJ32A2EKUHxf6fEgnr4Rcp4rkNO8G++rtqu4E", key.fingerprint)
        self.assertTrue(key.public_key.startswith("ssh-rsa"))

    def test_ex_edit_key_pair_param_name(self):
        existing_key = self.driver.get_key_pair("testkey1")
        key = self.driver.ex_edit_key_pair(existing_key, name="testkey_edit")
        self.assertTrue(key.extra["id"] == "224")

    def test_ex_edit_key_pair_param_default(self):
        existing_key = self.driver.get_key_pair("testkey1")
        key = self.driver.ex_edit_key_pair(existing_key, default=False)
        self.assertTrue(key.extra["id"] == "224")

    def test_delete_key_pair(self):
        key = self.driver.get_key_pair("testkey1")
        self.assertTrue(self.driver.delete_key_pair(key))

    def test_ex_get_node(self):
        node = self.driver.ex_get_node("server-red")
        self.assertEqual("server-red", node.name)

    def test_ex_edit_node_tags(self):
        existing_node = self.driver.ex_get_node("server-red")
        tags = [{"name": "test_name", "value": "test_value"}]
        node = self.driver.ex_edit_node_tags(existing_node, tags)
        self.assertEqual("server-red", node.name)
        self.assertEqual("test_name", node.extra["tags"][0]["name"])
        self.assertEqual("test_value", node.extra["tags"][0]["value"])

    def test_ex_edit_node_add_ip_block(self):
        node = self.driver.ex_get_node("server-red")
        ip_block = self.driver.ex_get_ip_block_by_id("6047127fed34ecc3ba8402d2")
        node = self.driver.ex_edit_node_add_ip_block(node, ip_block)
        self.assertEqual("12", node["id"])

    def test_ex_edit_node_remove_ip_block(self):
        node = self.driver.ex_get_node("server-red")
        ip_block = self.driver.ex_get_ip_block_by_id("6047127fed34ecc3ba8402d2")
        node = self.driver.ex_edit_node_remove_ip_block(node, ip_block)
        self.assertTrue(node)

    def test_ex_edit_node_add_private_network(self):
        existing_node = self.driver.ex_get_node("server-red")
        private_network = {"id": "34"}
        node = self.driver.ex_edit_node_add_private_network(
            existing_node, private_network
        )
        self.assertEqual("34", node["id"])

    def test_ex_edit_node_remove_private_network(self):
        existing_node = self.driver.ex_get_node("server-red")
        private_network = self.driver.ex_get_private_network("test")
        node = self.driver.ex_edit_node_remove_private_network(
            existing_node, private_network
        )
        self.assertTrue(node)

    def test_ex_edit_node_add_public_network(self):
        existing_node = self.driver.ex_get_node("server-red")
        public_network = {"id": "56", "ips": ["182.16.0.146", "182.16.0.147"]}
        node = self.driver.ex_edit_node_add_public_network(
            existing_node, public_network
        )
        self.assertEqual("56", node["id"])
        self.assertEqual(2, len(node["ips"]))

    def test_ex_edit_node_remove_public_network(self):
        existing_node = self.driver.ex_get_node("server-red")
        public_network = self.driver.ex_get_public_network("test")
        node = self.driver.ex_edit_node_remove_public_network(
            existing_node, public_network
        )
        self.assertTrue(node)

    def test_ex_create_tag(self):
        tag = self.driver.ex_create_tag("test")
        self.assertEqual("test", tag.name)

    def test_ex_list_tags(self):
        tags = self.driver.ex_list_tags()
        self.assertEqual(1, len(tags))
        self.assertEqual("test", tags[0].name)

    def test_ex_get_tag(self):
        tag = self.driver.ex_get_tag("test")
        self.assertEqual("test", tag.name)

    def test_ex_edit_tag_param_name(self):
        tag = self.driver.ex_get_tag("test")
        tag_edit = self.driver.ex_edit_tag(tag, name="edit")
        self.assertEqual("edit", tag_edit.description)

    def test_ex_edit_tag_param_is_billing_tag(self):
        tag = self.driver.ex_get_tag("test")
        tag_edit = self.driver.ex_edit_tag(tag, is_billing_tag=False)
        self.assertEqual(False, tag_edit.is_billing_tag)

    def test_ex_edit_tag_param_description(self):
        tag = self.driver.ex_get_tag("test")
        tag_edit = self.driver.ex_edit_tag(tag, description="edit")
        self.assertEqual("edit", tag_edit.description)

    def test_ex_delete_tag(self):
        tag = self.driver.ex_get_tag("test")
        self.assertTrue(self.driver.ex_delete_tag(tag))

    def test_ex_create_ip_block(self):
        ip_block = self.driver.ex_create_ip_block("PHX", "/31")
        self.assertEqual("PHX", ip_block.location)
        self.assertEqual("/31", ip_block.cidr_block_size)
        self.assertEqual("test", ip_block.description)

    def test_ex_list_ip_blocks(self):
        ip_blocks = self.driver.ex_list_ip_blocks()
        self.assertEqual(1, len(ip_blocks))
        self.assertEqual("test", ip_blocks[0].description)

    def test_ex_get_ip_block_by_id(self):
        ip_block = self.driver.ex_get_ip_block_by_id("6047127fed34ecc3ba8402d2")
        self.assertEqual("PHX", ip_block.location)
        self.assertEqual("/31", ip_block.cidr_block_size)
        self.assertEqual("test", ip_block.description)

    def test_ex_edit_ip_block_by_id(self):
        ip_block = self.driver.ex_edit_ip_block_by_id(
            "6047127fed34ecc3ba8402d2", "edit"
        )
        self.assertEqual("edit", ip_block.description)

    def test_ex_edit_ip_block_tags_by_id(self):
        tags = {"name": "edit_name", "value": "edit_value"}
        ip_block = self.driver.ex_edit_ip_block_tags_by_id(
            "6047127fed34ecc3ba8402d2", tags
        )
        self.assertEqual(1, len(ip_block.tags))
        self.assertEqual("edit_name", ip_block.tags[0]["name"])
        self.assertEqual("edit_value", ip_block.tags[0]["value"])

    def test_ex_delete_ip_block_by_id(self):
        self.assertTrue(
            self.driver.ex_delete_ip_block_by_id("6047127fed34ecc3ba8402d2")
        )

    def test_ex_create_private_network(self):
        private_network = self.driver.ex_create_private_network(
            "test", "PHX", "10.0.0.0/24"
        )
        self.assertEqual("test", private_network.name)
        self.assertEqual("PHX", private_network.location)
        self.assertEqual("10.0.0.0/24", private_network.cidr)

    def test_ex_list_private_networks(self):
        private_networks = self.driver.ex_list_private_networks()
        self.assertEqual(1, len(private_networks))
        self.assertEqual("test", private_networks[0].name)

    def test_ex_get_private_network(self):
        private_network = self.driver.ex_get_private_network("test")
        self.assertEqual("test", private_network.name)

    def test_ex_edit_private_network_param_name(self):
        private_network = self.driver.ex_get_private_network("test")
        private_network_edit = self.driver.ex_edit_private_network(
            private_network, "edit"
        )
        self.assertEqual("edit", private_network_edit.name)

    def test_ex_edit_private_network_param_description(self):
        private_network = self.driver.ex_get_private_network("test")
        private_network_edit = self.driver.ex_edit_private_network(
            private_network, description="edit"
        )
        self.assertEqual("edit", private_network_edit.description)

    def test_ex_edit_private_network_param_location_default(self):
        private_network = self.driver.ex_get_private_network("test")
        private_network_edit = self.driver.ex_edit_private_network(
            private_network, location_default=True
        )
        self.assertEqual(True, private_network_edit.location_default)

    def test_ex_delete_private_network(self):
        private_network = self.driver.ex_get_private_network("test")
        self.assertTrue(self.driver.ex_delete_private_network(private_network))

    def test_ex_create_public_network(self):
        ip_block = self.driver.ex_create_ip_block("PHX", "/28")
        public_network = self.driver.ex_create_public_network(
            "test", "PHX", ip_blocks=ip_block
        )
        self.assertEqual("test", public_network.name)
        self.assertEqual("PHX", public_network.location)

    def test_ex_list_public_networks(self):
        public_networks = self.driver.ex_list_public_networks()
        self.assertEqual(1, len(public_networks))
        self.assertEqual("test", public_networks[0].name)

    def test_ex_get_public_network(self):
        public_network = self.driver.ex_get_public_network("test")
        self.assertEqual("test", public_network.name)

    def test_ex_edit_public_network_param_name(self):
        public_network = self.driver.ex_get_public_network("test")
        public_network_edit = self.driver.ex_edit_public_network(
            public_network, name="edit"
        )
        self.assertEqual("edit", public_network_edit.name)

    def test_ex_edit_public_network_param_description(self):
        public_network = self.driver.ex_get_public_network("test")
        public_network_edit = self.driver.ex_edit_public_network(
            public_network, description="edit"
        )
        self.assertEqual("edit", public_network_edit.description)

    def test_edit_public_network_add_ip_block(self):
        public_network = self.driver.ex_get_public_network("test")
        public_network_edit = self.driver.ex_edit_public_network_add_ip_block(
            public_network, "123"
        )
        self.assertEqual(
            "60473a6115e34466c9f8f083", public_network_edit.ip_blocks[0]["id"]
        )

    def test_ex_edit_public_network_remove_ip_block(self):
        public_network = self.driver.ex_get_public_network("test")
        public_network_edit = self.driver.ex_edit_public_network_remove_ip_block(
            public_network, "123"
        )
        self.assertEqual(1, len(public_network_edit.ip_blocks))

    def test_ex_delete_public_network(self):
        public_network = self.driver.ex_get_public_network("test")
        self.assertTrue(self.driver.ex_delete_public_network(public_network))

    def test_ex_get_products(self):
        products = self.driver.ex_get_products()
        self.assertTrue(len(products) > 1)

    def test_ex_get_product_availability(self):
        product_availability = self.driver.ex_get_product_availability()
        self.assertTrue(len(product_availability) > 1)

    def test_ex_get_account_billing_configurations(self):
        billing_confifurations = self.driver.ex_get_account_billing_configurations()
        self.assertEqual(
            100, billing_confifurations["thresholdConfiguration"]["thresholdAmount"]
        )

    def test_ex_get_rated_usage(self):
        rated_usage = self.driver.ex_get_rated_usage("2022-07", "2022-08")
        self.assertTrue(len(rated_usage) > 1)

    def test_ex_get_rated_usage_month_to_date(self):
        rated_usage = self.driver.ex_get_rated_usage_month_to_date()
        self.assertTrue(len(rated_usage) > 1)

    def test_ex_get_events(self):
        events = self.driver.ex_get_events()
        self.assertTrue(len(events) > 1)

    def test_ex_create_reservation(self):
        reservation = self.driver.ex_create_reservation("123")
        self.assertEqual("123", reservation["id"])

    def test_ex_list_reservations(self):
        reservations = self.driver.ex_list_reservations()
        self.assertEqual(3, len(reservations))

    def test_ex_edit_reservation_auto_renew_enable(self):
        reservation = self.driver.ex_edit_reservation_auto_renew_enable("123")
        self.assertEqual("123", reservation["id"])
        self.assertTrue(reservation["autoRenew"])

    def test_ex_edit_reservation_auto_renew_disable(self):
        reservation = self.driver.ex_edit_reservation_auto_renew_disable("123", "test")
        self.assertEqual("123", reservation["id"])
        self.assertFalse(reservation["autoRenew"])

    def test_ex_edit_reservation_convert(self):
        reservation = self.driver.ex_edit_reservation_convert("123", "U5WC-EDGC-REYH")
        self.assertEqual("123", reservation["id"])
        self.assertEqual("U5WC-EDGC-REYH", reservation["sku"])

    def test_ex_create_rancher_cluster(self):
        cluster = self.driver.ex_create_rancher_cluster("PHX")
        self.assertEqual("PHX", cluster["location"])
        self.assertEqual("Rancher Deployment", cluster["name"])
        self.assertEqual("Rancher Server Node Pool", cluster["nodePools"][0]["name"])

    def test_ex_list_rancher_clusters(self):
        cluster = self.driver.ex_list_rancher_clusters()
        self.assertEqual(1, len(cluster))
        self.assertEqual("Rancher Deployment", cluster[0]["name"])

    def test_ex_delete_rancher_cluster_by_id(self):
        self.assertTrue(self.driver.ex_delete_rancher_cluster_by_id("123"))

    def test_ex_create_storage_network(self):
        storage_network = self.driver.ex_create_storage_network(
            "test", "PHX", {"name": "myvolume", "capacityInGb": 1000}, "desc"
        )
        self.assertEqual("test create", storage_network.name)
        self.assertEqual("PHX", storage_network.location)
        self.assertEqual("desc", storage_network.description)
        self.assertEqual("myvolume", storage_network.volumes[0]["name"])
        self.assertEqual(1000, storage_network.volumes[0]["capacityInGb"])

    def test_ex_list_storage_networks(self):
        storage_networks = self.driver.ex_list_storage_networks()
        self.assertEqual(1, len(storage_networks))
        self.assertEqual("test", storage_networks[0].name)

    def test_ex_get_storage_network(self):
        storage_network = self.driver.ex_get_storage_network("test")
        self.assertEqual("test", storage_network.name)

    def test_ex_edit_storage_network_param_name(self):
        storage_network = self.driver.ex_get_storage_network("test")
        storage_network_edit = self.driver.ex_edit_storage_network(
            storage_network, name="test edit"
        )
        self.assertEqual("test edit", storage_network_edit.name)

    def test_ex_edit_storage_network_param_description(self):
        storage_network = self.driver.ex_get_storage_network("test")
        storage_network_edit = self.driver.ex_edit_storage_network(
            storage_network, description="desc edit"
        )
        self.assertEqual("desc edit", storage_network_edit.description)

    def test_ex_delete_storage_network(self):
        storage_network = self.driver.ex_get_storage_network("test")
        self.assertTrue(self.driver.ex_delete_storage_network(storage_network))

    def test_ex_get_volumes_by_storage_network_id(self):
        volumes = self.driver.ex_get_volumes_by_storage_network_id("123")
        self.assertEqual("myvolume", volumes[0]["name"])

    def test_ex_get_volume_by_id(self):
        volume = self.driver.ex_get_volume_by_id("12345")
        self.assertEqual("myvolume-test", volume["name"])


class PnapBmcMockHttp(MockHttp):
    fixtures = ComputeFileFixtures("pnap_bmc")

    def _bmc_v1_servers(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("list_nodes.json")
        else:
            body = self.fixtures.load("create_node.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_products(self, method, url, body, headers):
        body = self.fixtures.load("list_sizes.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_actions_shutdown(self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_actions_power_on(self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_actions_reboot(self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_actions_power_off(self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123(self, method, url, body, headers):
        body = self.fixtures.load("create_node.json")
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _bmc_v1_servers_123_actions_deprovision(self, method, url, body, headers):
        return (httplib.ACCEPTED, "", {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_ssh_keys(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("list_key_pairs.json")
        else:
            body = self.fixtures.load("import_key_pair.json")
        return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _bmc_v1_ssh_keys_123(self, method, url, body, headers):
        if method == "delete":
            return (httplib.OK, "", {}, "httplib.responses[httplib.OK]")
        else:
            body = self.fixtures.load("import_key_pair.json")
            return (httplib.OK, body, {}, httplib.responses[httplib.OK])

    def _bmc_v1_servers_123_tags(self, method, url, body, headers):
        body = self.fixtures.load("ex_edit_node_tags.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_ip_block_configurations_ip_blocks(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_add_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_ip_block_configurations_ip_blocks_12(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_remove_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_private_network_configuration_private_networks(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_add_private_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_private_network_configuration_private_networks_604724a5a807f2d3be8660c7(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_remove_private_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_public_network_configuration_public_networks(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_add_public_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _bmc_v1_servers_123_network_configuration_public_network_configuration_public_networks_60472f76bbadb4f36541d2fd(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_node_remove_public_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _tag_manager_v1_tags(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_tags.json")
        else:
            body = self.fixtures.load("ex_create_tag.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _tag_manager_v1_tags_619fa8f7c5b096091f41076e(self, method, url, body, headers):
        if method == "DELETE":
            body = self.fixtures.load("ex_delete_tag.json")
        elif method == "PATCH":
            body = self.fixtures.load("ex_edit_tag.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _ips_v1_ip_blocks(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_ip_blocks.json")
        else:
            body = self.fixtures.load("ex_create_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _ips_v1_ip_blocks_6047127fed34ecc3ba8402d2(self, method, url, body, headers):
        if method == "PATCH":
            body = self.fixtures.load("ex_edit_ip_block.json")
        elif method == "DELETE":
            body = self.fixtures.load("ex_delete_ip_block.json")
        else:
            body = self.fixtures.load("ex_create_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _ips_v1_ip_blocks_6047127fed34ecc3ba8402d2_tags(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_ip_block_tags.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_private_networks(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_private_networks.json")
        else:
            body = self.fixtures.load("ex_create_private_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_private_networks_604724a5a807f2d3be8660c7(
        self, method, url, body, headers
    ):
        if method == "DELETE":
            body = self.fixtures.load("ex_delete_private_network.json")
        else:
            body = self.fixtures.load("ex_edit_private_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_public_networks(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_public_networks.json")
        else:
            body = self.fixtures.load("ex_create_public_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_public_networks_60472f76bbadb4f36541d2fd(
        self, method, url, body, headers
    ):
        if method == "DELETE":
            body = self.fixtures.load("ex_delete_public_network.json")
        else:
            body = self.fixtures.load("ex_edit_public_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_public_networks_60472f76bbadb4f36541d2fd_ip_blocks_123(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_public_network_remove_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _networks_v1_public_networks_60472f76bbadb4f36541d2fd_ip_blocks(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_public_network_add_ip_block.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_product_availability(self, method, url, body, headers):
        body = self.fixtures.load("ex_get_product_availability.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_account_billing_configurations_me(self, method, url, body, headers):
        body = self.fixtures.load("ex_get_account_billing_configurations.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_rated_usage(self, method, url, body, headers):
        body = self.fixtures.load("ex_get_rated_usage.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_rated_usage_month_to_date(self, method, url, body, headers):
        body = self.fixtures.load("ex_get_rated_usage.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _audit_v1_events(self, method, url, body, headers):
        body = self.fixtures.load("ex_get_events.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_reservations(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_reservations.json")
        else:
            body = self.fixtures.load("ex_create_reservation.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_reservations_123_actions_auto_renew_enable(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_reservation_auto_renew_enable.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_reservations_123_actions_auto_renew_disable(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_edit_reservation_auto_renew_disable.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _billing_v1_reservations_123_actions_convert(self, method, url, body, headers):
        body = self.fixtures.load("ex_edit_reservation_convert.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _solutions_rancher_v1beta_clusters(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_rancher_clusters.json")
        else:
            body = self.fixtures.load("ex_create_rancher_cluster.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _solutions_rancher_v1beta_clusters_123(self, method, url, body, headers):
        body = self.fixtures.load("ex_delete_rancher_cluster.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _network_storage_v1_storage_networks(self, method, url, body, headers):
        if method == "GET":
            body = self.fixtures.load("ex_list_storage_networks.json")
        else:
            body = self.fixtures.load("ex_create_storage_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _network_storage_v1_storage_networks_603f3b2cfcaf050643b89a4b(
        self, method, url, body, headers
    ):
        if method == "DELETE":
            body = self.fixtures.load("ex_delete_storage_network.json")
        else:
            body = self.fixtures.load("ex_edit_storage_network.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])

    def _network_storage_v1_storage_networks_123_volumes(
        self, method, url, body, headers
    ):
        body = self.fixtures.load("ex_get_volumes_by_storage_network_id.json")
        return (httplib.ACCEPTED, body, {}, httplib.responses[httplib.ACCEPTED])


if __name__ == "__main__":
    sys.exit(unittest.main())
