from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

private_network = driver.ex_create_private_network('my_private_network',
                                                   'PHX',
                                                   '10.0.0.0/24',
                                                   description='desc')
print(private_network)

# List all Private Networks owned by account
# for private_network in driver.ex_list_private_networks():
   # print(private_networks)

# Delete the Private Network
# private_network = driver.ex_get_private_network_by_name('my_private_network')
# driver.ex_delete_private_network(private_network)