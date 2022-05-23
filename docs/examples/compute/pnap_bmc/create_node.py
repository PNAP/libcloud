from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
import os

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

size = [s for s in driver.list_sizes() if s.name == 's1.c1.small'][0]
image = [i for i in driver.list_images() if i.name == 'ubuntu/bionic'][0]
location = [i for i in driver.list_locations() if i.name == 'PHOENIX'][0]

with open(os.path.expanduser('~/.ssh/id_rsa.pub')) as file:
    ssh_key = file.read()

node = driver.create_node('mynode', size, image, location, 
                          ex_ssh_keys=[ssh_key], 
                          ex_description='desc')                  
print(node)
print(node.extra)