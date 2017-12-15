**************************
nginx-dav-ext-xattr-module
**************************

NGINX WebDAV missing commands support (PROPFIND & OPTIONS) and xattr properties


| Copyright |copy| 2012-2017 Arutyunyan Roman (arutyunyan.roman@gmail.com)
| Copyright |copy| 2017 Green Communications (qolyester@green-communcations.fr)
|

.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

For full WebDAV support in NGINX you need to enable the standard NGINX
WebDAV module (providing partial WebDAV implementation) as well as
this module for missing methods:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-module=/path/to/this-module

The module can be built dynamically:

.. code-block:: bash

    $ ./configure --with-http_dav_module --add-dynamic-module=/path/to/this-module

Requirements
============

``libexpat-dev``
``libglib2-dev``


Example config
==============

.. code-block::

	location / {
		dav_methods PUT DELETE MKCOL COPY MOVE;
		dav_ext_methods PROPFIND OPTIONS;
		dav_ext_getxattr ^somenamespace\.*$;

		root /var/root/;
	}
