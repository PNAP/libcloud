from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
import os

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

key_file_path = os.path.expanduser('~/.ssh/id_rsa.pub')
ssh_key = driver.import_key_pair_from_file('mykey', key_file_path, default=True)

print(ssh_key)