from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

tag = driver.ex_create_tag('my_tag', description='dev')
print(tag)

# Delete the tag
# tag = driver.ex_get_tag('my_tag')
# driver.ex_delete_tag(tag)
