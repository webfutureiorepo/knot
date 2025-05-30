.. _mod-dnsproxy:

``dnsproxy`` – Tiny DNS proxy
=============================

The module forwards all queries, or all specific zone queries if configured
per zone, to the indicated server for resolution. If configured in the fallback
mode, only locally unsatisfied queries are forwarded. I.e. a tiny DNS proxy.
There are several uses of this feature:

* A substitute public-facing server in front of the real one
* Local zones (poor man's "views"), rest is forwarded to the public-facing server
* Using the fallback to forward queries to a resolver
* etc.

.. NOTE::
   The module does not alter the query/response as the resolver would,
   and the original transport protocol (UDP or TCP) is kept as well.

Example
-------

The configuration is straightforward and just a single remote server is
required::

   remote:
     - id: hidden
       address: 10.0.1.1

   mod-dnsproxy:
     - id: default
       remote: hidden
       fallback: on

   template:
     - id: default
       global-module: mod-dnsproxy/default

   zone:
     - domain: local.zone

When a client queries anything in the ``local.zone`` (which must exist),
it will receive a local response. All other requests (to unknown zones)
will be forwarded to the specified server (``10.0.1.1`` in this case).

Module reference
----------------

::

 mod-dnsproxy:
   - id: STR
     remote: remote_id
     timeout: INT
     address: ADDR[/INT] | ADDR-ADDR | STR ...
     fallback: BOOL
     tcp-fastopen: BOOL
     catch-nxdomain: BOOL

.. _mod-dnsproxy_id:

id
..

A module identifier.

.. _mod-dnsproxy_remote:

remote
......

A :ref:`reference<remote_id>` to a remote server where the queries are
forwarded to.

*Required*

.. NOTE::
   If the remote has more addresses configured, other addresses are used
   sequentially as fallback. In this case, for the N-th address the N-th via address
   is taken if configured.

.. _mod-dnsproxy_timeout:

timeout
.......

A remote response timeout in milliseconds.

*Default:* ``500`` (milliseconds)

.. _mod-dnsproxy_address:

address
.......

An ordered list of IP addresses, absolute UNIX socket paths, network subnets,
or network ranges.
If the query's source address does not fall into any of the configured ranges, the
query isn't forwarded.

*Default:* not set

.. _mod-dnsproxy_fallback:

fallback
........

If enabled, locally unsatisfied queries leading to REFUSED (no zone) are forwarded.
If disabled, all queries are directly forwarded without any local attempts
to resolve them.

*Default:* ``on``

.. _mod-dnsproxy_tcp-fastopen:

tcp-fastopen
............

If enabled, TCP Fast Open is used when forwarding TCP queries.

*Default:* ``off``

.. _mod-dnsproxy_catch-nxdomain:

catch-nxdomain
..............

If enabled, locally unsatisfied queries leading to NXDOMAIN are forwarded.
This option is only relevant in the fallback mode.

*Default:* ``off``
