from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

driver.ex_create_tag("libcloud1")
driver.ex_create_tag("libcloud2")

tags = [
    {'name': 'libcloud1', 'value': 'value1'},
    {'name': 'libcloud2', 'value': 'value2'}
]

ip_block = driver.ex_create_ip_block('PHX', '/31', 
                                     description='my_desc', 
                                     tags=tags)

print(ip_block)

# List all IP Blocks owned by account
# for ip_block in driver.ex_list_ip_blocks():
#     print(ip_block)

# Delete the IP Block and tags
# driver.ex_delete_ip_block_by_id('yourIPBlockId')
# for tag in driver.ex_list_tags():
#     if tag.name.startswith('libcloud'):
#         driver.ex_delete_tag(tag)