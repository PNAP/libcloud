from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

volumes = {"name": "myvolume", "capacityInGb": 1000}
storage_network = driver.ex_create_storage_network('My storage network',
                                                   'PHX',
                                                   volumes,
                                                   'my description')
print(storage_network)

# List all Storage Networks owned by account
# for storage_network in driver.ex_list_storage_networks():
#    print(storage_networks)

# Delete the Storage Network
# storage_network = driver.ex_get_storage_network('My storage network')
# driver.ex_delete_storage_network(storage_network)