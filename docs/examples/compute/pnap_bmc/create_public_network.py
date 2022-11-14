from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

ip_block = driver.ex_create_ip_block('PHX', '/29', 'my description')
public_network = driver.ex_create_public_network('my_public_network', 
                                                 'PHX',
                                                 'my description',
                                                 ip_block
                                                )
print(public_network)

# List all Public Networks owned by account
# for public_network in driver.ex_list_public_networks():
    # print(public_network)

# Delete the Public Network
# public_network = driver.ex_get_public_network('my_public_network')
# driver.ex_delete_public_network(public_network)