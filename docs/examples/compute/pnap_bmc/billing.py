from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

PNAP_CLIENT_ID = 'my_client_id'
PNAP_CLIENT_SECRET = 'my_client_secret'

cls = get_driver(Provider.PNAP_BMC)
driver = cls(PNAP_CLIENT_ID, PNAP_CLIENT_SECRET)

#Retrieves billing configuration associated with the authenticated account.
print(driver.ex_get_account_billing_configurations())

#Retrieves the list of product availability details.
print(driver.ex_get_products())

print(driver.ex_get_products(product_category='SERVER', 
                             location='PHX',
                             product_code='c1.medium'))

#Retrieves the list of product availability details.
print(driver.ex_get_product_availability())

print(driver.ex_get_product_availability(product_category=['SERVER'],
                                         product_code=['d1.c1.small', 'd1.c2.small'],
                                         location=['PHX'], min_quantity=1))

#Retrieves all rated usage for given time period.
print(driver.ex_get_rated_usage(from_year_month='2022-05',
                                to_year_month='2022-07'))

#Retrieves all rated usage for the current calendar month.
print(driver.ex_get_rated_usage_month_to_date())

print(driver.ex_get_rated_usage_month_to_date(product_category='SERVER'))

#Creates new package reservation for authenticated account.
print(driver.ex_create_reservation('USXA-JYST-F2JQ'))

#Disable auto-renewal for reservation by reservation id.
print(driver.ex_edit_reservation_auto_renew_disable('xyz', 'reason'))

#Enable auto-renewal for unexpired reservation by reservation id.
print(driver.ex_edit_reservation_auto_renew_enable('xyz'))

#Convert reservation pricing model by reservation id.
print(driver.ex_edit_reservation_convert('xyz' , 'U5WC-EDGC-REYH'))

#Retrieves the event logs for given time period. All date & times are in UTC.
print(driver.ex_get_events())

print(driver.ex_get_events(from_date='2021-05-29T16:24:57.123Z',
                           to_date='2021-06-29T16:24:57.123Z',
                           limit=2, verb='POST',
                           uri='/bmc/v1/servers/',
                           order='DESC'))
