.. _mod-dnstap:

``dnstap`` – Dnstap traffic logging
===================================

A module for query and response logging based on the dnstap_ library.
You can capture either all or zone-specific queries and responses; usually
you want to do the former.

Example
-------

The configuration comprises only a :ref:`mod-dnstap_sink` path parameter,
which can be either a file, a UNIX socket, or a TCP address::

   mod-dnstap:
     - id: capture_all
       sink: /tmp/capture.tap

   template:
     - id: default
       global-module: mod-dnstap/capture_all

.. NOTE::
   To be able to use a Unix socket you need an external program to create it.
   Knot DNS connects to it as a client using the libfstrm library. It operates
   exactly like syslog.

.. NOTE::
   Dnstap log files can also be created or read using :doc:`kdig<man_kdig>`.

.. _dnstap: https://dnstap.info/

Module reference
----------------

For all queries logging, use this module in the *default* template. For
zone-specific logging, use this module in the proper zone configuration.

::

 mod-dnstap:
   - id: STR
     sink: STR
     identity: STR
     version: STR
     log-queries: BOOL
     log-responses: BOOL
     responses-with-queries: BOOL

.. _mod-dnstap_id:

id
..

A module identifier.

.. _mod-dnstap_sink:

sink
....

A sink path, which can be either a file, a UNIX socket when prefixed with
``unix:``, or a TCP `address@port` when prefixed with ``tcp:``. The file may
be specified as an absolute path or a path relative to
the :doc:`knotd<man_knotd>` startup directory.

*Required*

.. WARNING::
   File is overwritten on server startup or reload.

.. _mod-dnstap_identity:

identity
........

A DNS server identity. Set empty value to disable.

*Default:* FQDN hostname

.. _mod-dnstap_version:

version
.......

A DNS server version. Set empty value to disable.

*Default:* server version

.. _mod-dnstap_log-queries:

log-queries
...........

If enabled, query messages will be logged.

*Default:* ``on``

.. _mod-dnstap_log-responses:

log-responses
.............

If enabled, response messages will be logged.

*Default:* ``on``

responses-with-queries
......................

If enabled, dnstap ``AUTH_RESPONSE`` messages will also include the original
query message as well as the response message sent by the server.

*Default:* ``off``
