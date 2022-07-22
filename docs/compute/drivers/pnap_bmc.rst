phoenixNAP BMC (pnap_bmc) Driver Documentation
==============================================

`phoenixNAP Bare Metal Cloud`_ delivers cloud agility without the hypervisor overhead. We built Bare Metal Cloud to help you deploy and manage physical servers with cloud-like ease and simplicity.

Instantiating a driver
----------------------

When you instantiate a driver you need to pass the following arguments to the
driver constructor:

* ``PNAP_CLIENT_ID`` - Your Client ID
* ``PNAP_CLIENT_SECRET`` - Your Client Secret

With these credentials you can instantiate a driver:

.. literalinclude:: /examples/compute/pnap_driver/instantiate_driver.py
   :language: python

Examples
--------

Create a Server (node)
~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_node.py
   :language: python

Create an SSH Key
~~~~~~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_ssh_key.py
   :language: python

Create a Tag
~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_tag.py
   :language: python

Create an IP Block
~~~~~~~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_ip_block.py
   :language: python

Create a Private Network
~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_private_network.py
   :language: python

Create a Public Network
~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: /examples/compute/pnap_bmc/create_public_network.py
   :language: python

API Docs
--------

.. autoclass:: libcloud.compute.drivers.pnap_bmc.PnapBmcNodeDriver
    :members:
    :inherited-members:

.. _`phoenixNAP Bare Metal Cloud`: https://phoenixnap.com/bare-metal-cloud
