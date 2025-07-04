.. highlight:: none
.. _Configuration:

*************
Configuration
*************

Simple configuration
====================

The following example presents a simple configuration file
which can be used as a base for your Knot DNS setup::

    # Example of a very simple Knot DNS configuration.

    server:
        listen: 0.0.0.0@53
        listen: ::@53

    zone:
      - domain: example.com
        storage: /var/lib/knot/zones/
        file: example.com.zone

    log:
      - target: syslog
        any: info

Now let's walk through this configuration step by step:

- The :ref:`server_listen` statement in the :ref:`server section<Server section>`
  defines where the server will listen for incoming connections.
  We have defined the server to listen on all available IPv4 and IPv6 addresses,
  all on port 53.
- The :ref:`zone section` defines the zones that the server will
  serve. In this case, we defined one zone named *example.com* which is stored
  in the zone file :file:`/var/lib/knot/zones/example.com.zone`.
- The :ref:`log section` defines the log facilities for
  the server. In this example, we told Knot DNS to send its log messages with
  the severity ``info`` or more serious to the syslog (or systemd journal).

For detailed description of all configuration items see
:ref:`Configuration Reference`.

Zone templates
==============

A zone template allows a single zone configuration to be shared among several
zones. There is no inheritance between templates; they are exclusive. The
``default`` template identifier is reserved for the default template::

    template:
      - id: default
        storage: /var/lib/knot/master
        semantic-checks: on

      - id: signed
        storage: /var/lib/knot/signed
        dnssec-signing: on
        semantic-checks: on
        master: [master1, master2]

      - id: slave
        storage: /var/lib/knot/slave

    zone:
      - domain: example1.com     # Uses default template

      - domain: example2.com     # Uses default template
        semantic-checks: off     # Override default settings

      - domain: example.cz
        template: signed
        master: master3          # Override masters to just master3

      - domain: example1.eu
        template: slave
        master: master1

      - domain: example2.eu
        template: slave
        master: master2

.. NOTE::
   Each template option can be explicitly overridden in zone-specific configuration.

.. _ACL:

Access control list (ACL)
=========================

Normal DNS queries are always allowed. All other DNS requests must be
authorized before they can be processed by the server. A zone can have
configured :ref:`ACL <ACL section>` which is a sequence of rules describing
what requests are authorized. An :ref:`automatic ACL <server_automatic-acl>`
feature can be used to simplify ACL management.

Every ACL rule can allow or deny one or more request types (:ref:`actions <acl_action>`)
based on the source IP address, network subnet, address range, protocol,
remote certificate key PIN and/or
if the request is secured by a given TSIG key. See :doc:`keymgr -t<man_keymgr>`
on how to generate a TSIG key.

If there are multiple ACL rules assigned to a zone, they are applied in the
specified order of the :ref:`zone_acl` configuration. The first rule that matches
the given request is applied and the remaining rules are ignored. Some examples::

    acl:
      - id: address_rule
        address: [2001:db8::1, 192.168.2.0/24]
        action: transfer

      - id: deny_rule
        address: 192.168.2.100
        action: transfer
        deny: on

    zone:
      - domain: acl1.example.com
        acl: [deny_rule, address_rule]     # Allow some addresses with an exception

::

    key:
      - id: key1                           # The real TSIG key name
        algorithm: hmac-sha256
        secret: 4Tc0K1QkcMCs7cOW2LuSWnxQY0qysdvsZlSb4yTN9pA=

    acl:
      - id: deny_all
        address: 192.168.3.0/24
        deny: on                           # No action specified and deny on implies denial of all actions

      - id: key_rule
        key: key1                          # Access based just on TSIG key
        action: [transfer, notify]

    zone:
      - domain: acl2.example.com
        acl: [deny_all, key_rule]          # Allow with the TSIG except for the subnet

In the case of dynamic DNS updates, some additional conditions may be specified
for more granular filtering. See more in the section :ref:`Restricting dynamic updates`.

.. NOTE::
   If more conditions (address ranges and/or a key)
   are given in a single ACL rule, all of them have to be satisfied for the rule to match.

.. TIP::
   In order to restrict regular DNS queries, use module :ref:`queryacl<mod-queryacl>`.

Secondary (slave) zone
======================

Knot DNS doesn't strictly differ between primary (formerly known as master)
and secondary (formerly known as slave) zones. The only requirement for a secondary
zone is to have a :ref:`zone_master` statement set. For effective zone synchronization,
incoming zone change notifications (NOTIFY), which require authorization, can be
enabled using :ref:`automatic ACL <server_automatic-acl>` or :ref:`explicit ACL <zone_acl>`
configuration. Optional transaction authentication (TSIG) is supported for both
zone transfers and zone notifications::

    server:
        automatic-acl: on                     # Enabled automatic ACL

    key:
      - id: xfr_notify_key                    # Common TSIG key for XFR an NOTIFY
        algorithm: hmac-sha256
        secret: VFRejzw8h4M7mb0xZKRFiZAfhhd1eDGybjqHr2FV3vc=

    remote:
      - id: primary
        address: [2001:DB8:1::1, 192.168.1.1] # Primary server IP addresses
        # via: [2001:DB8:2::1, 10.0.0.1]      # Local source addresses (optional)
        key: xfr_notify_key                   # TSIG key (optional)

    zone:
      - domain: example.com
        master: primary                       # Primary remote(s)

An example of explicit ACL with different TSIG keys for zone transfers
and notifications::

    key:
      - id: notify_key                        # TSIG key for NOTIFY
        algorithm: hmac-sha256
        secret: uBbhV4aeSS4fPd+wF2ZIn5pxOMF35xEtdq2ibi2hHEQ=

      - id: xfr_key                           # TSIG key for XFR
        algorithm: hmac-sha256
        secret: VFRejzw8h4M7mb0xZKRFiZAfhhd1eDGybjqHr2FV3vc=

    remote:
      - id: primary
        address: [2001:DB8:1::1, 192.168.1.1] # Primary server IP addresses
        # via: [2001:DB8:2::1, 10.0.0.1]      # Local source addresses if needed
        key: xfr_key                          # Optional TSIG key

    acl:
      - id: notify_from_primary               # ACL rule for NOTIFY from primary
        address: [2001:DB8:1::1, 192.168.1.1] # Primary addresses (optional)
        key: notify_key                       # TSIG key (optional)
        action: notify

    zone:
      - domain: example.com
        master: primary                       # Primary remote(s)
        acl: notify_from_primary              # Explicit ACL(s)

Note that the :ref:`zone_master` option accepts a list of remotes, which are
queried for a zone refresh sequentially in the specified order. When the server
receives a zone change notification from a listed remote, only that remote is
used for a subsequent zone transfer.

.. NOTE::
   When transferring a lot of zones, the server may easily get into a state
   where all available ports are in the TIME_WAIT state, thus transfers
   cease until the operating system closes the ports for good. There are
   several ways to work around this:

   * Allow reusing of ports in TIME_WAIT (sysctl -w net.ipv4.tcp_tw_reuse=1)
   * Shorten TIME_WAIT timeout (tcp_fin_timeout)
   * Increase available local port count

Primary (master) zone
=====================

A zone is considered primary if it doesn't have :ref:`zone_master` set. As
outgoing zone transfers (XFR) require authorization, it must be enabled
using :ref:`automatic ACL <server_automatic-acl>` or :ref:`explicit ACL <zone_acl>`
configuration. Outgoing zone change notifications (NOTIFY) to remotes can be
set by configuring :ref:`zone_notify`. Transaction authentication
(TSIG) is supported for both zone transfers and zone notifications::

    server:
        automatic-acl: on                     # Enabled automatic ACL

    key:
      - id: xfr_notify_key                    # Common TSIG key for XFR an NOTIFY
        algorithm: hmac-sha256
        secret: VFRejzw8h4M7mb0xZKRFiZAfhhd1eDGybjqHr2FV3vc=

    remote:
      - id: secondary
        address: [2001:DB8:1::1, 192.168.1.1] # Secondary server IP addresses
        # via: [2001:DB8:2::1, 10.0.0.1]      # Local source addresses (optional)
        key: xfr_notify_key                   # TSIG key (optional)

    acl:
      - id: local_xfr                         # Allow XFR to localhost without TSIG
        address: [::1, 127.0.0.1]
        action: transfer

    zone:
      - domain: example.com
        notify: secondary                     # Secondary remote(s)
        acl: local_xfr                        # Explicit ACL for local XFR

Note that the :ref:`zone_notify` option accepts a list of remotes, which are
all notified sequentially in the specified order.

A secondary zone may serve as a primary zone for a different set of remotes
at the same time.

.. _dynamic updates:

Dynamic updates
===============

Dynamic updates for the zone are allowed via proper ACL rule with the
``update`` action. If the zone is configured as a secondary and a DNS update
message is accepted, the server forwards the message to its first primary
:ref:`zone_master` or :ref:`zone_ddns-master` if configured.
The primary master's response is then forwarded back to the originator.

However, if the zone is configured as a primary, the update is accepted and
processed::

    acl:
      - id: update_acl
        address: 192.168.3.0/24
        action: update

    zone:
      - domain: example.com.
        acl: update_acl

.. NOTE::
   To forward DDNS requests signed with a locally unknown key, an ACL rule for
   the action ``update`` without a key must be configured for the zone. E.g.::

    acl:
      - id: fwd_foreign_key
        action: update
        # possible non-key options

    zone:
     - domain: example.com.
       acl: fwd_foreign_key

.. _Restricting dynamic updates:

Restricting dynamic updates
---------------------------

There are several additional ACL options for dynamic DNS updates which affect
the request classification based on the update contents.

Updates can be restricted to specific resource record types::

    acl:
      - id: type_rule
        action: update
        update-type: [A, AAAA, MX]    # Updated records must match one of the specified types

Another possibility is restriction on the owner name of updated records. The option
:ref:`acl_update-owner` is used to select the source of domain
names which are used for the comparison. And the option :ref:`acl_update-owner-match`
specifies the required relation between the record owner and the reference domain
names. Example::

    acl:
      - id: owner_rule1
        action: update
        update-owner: name             # Updated record owners are restricted by the next conditions
        update-owner-match: equal      # The record owner must exactly match one name from the next list
        update-owner-name: [foo, bar.] # Reference domain names

.. NOTE::
   If the specified owner name is non-FQDN (e.g. ``foo``), it's considered relatively
   to the effective zone name. So it can apply to more zones
   (e.g. ``foo.example.com.`` or ``foo.example.net.``). Alternatively, if the
   name is FQDN (e.g. ``bar.``), the rule only applies to this name.

If the reference domain name is the zone name, the following variant can be used::

    acl:
      - id: owner_rule2
        action: update
        update-owner: zone            # The reference name is the zone name
        update-owner-match: sub       # Any record owner matches except for the zone name itself

    template:
      - id: default
        acl: owner_rule2

    zone:
      - domain: example.com.
      - domain: example.net.

The last variant is for the cases where the reference domain name is a TSIG key name,
which must be used for the transaction security::

    key:
      - id: example.com               # Key names are always considered FQDN
        ...
      - id: steve.example.net
        ...
      - id: jane.example.net
        ...

    acl:
      - id: owner_rule3_com
        action: update
        update-owner: key             # The reference name is the TSIG key name
        update-owner-match: sub       # The record owner must be a subdomain of the key name
        key: [example.com]            # One common key for updating all non-apex records

      - id: owner_rule3_net
        action: update
        update-owner: key             # The reference name is the TSIG key name
        update-owner-match: equal     # The record owner must exactly match the used key name
        key: [steve.example.net, jane.example.net] # Keys for updating specific zone nodes

    zone:
     - domain: example.com.
       acl: owner_rule3_com
     - domain: example.net.
       acl: owner_rule3_net

.. _Handling CNAME and DNAME-related updates:

Handling CNAME and DNAME-related updates
----------------------------------------

In general, no RR must exist beside a CNAME or below a DNAME. Whenever
such a CNAME or DNAME-related semantic rule is vialoated by an RR addition
in DDNS (this means addition of a CNAME beside an existing record, addition of
another record beside a CNAME, addition of a DNAME above an existing record,
addition of another record below a DNAME), such an RR addition is silently ignored.
However, other RRs from the same DDNS update are processed normally. This is slightly
non-compliant with RFC 6672 (in particular, no RR occlusion takes place).

.. _dnssec:

Automatic DNSSEC signing
========================

Knot DNS supports automatic DNSSEC signing of zones. The signing
can operate in two modes:

1. :ref:`Manual key management <dnssec-manual-key-management>`:
   In this mode, the server maintains zone signatures (RRSIGs) only. The
   signatures are kept up-to-date and signing keys are rolled according to
   the timing parameters assigned to the keys. The keys must be generated and
   timing parameters must be assigned by the zone operator.

2. :ref:`Automatic key management <dnssec-automatic-zsk-management>`:
   In this mode, the server maintains signing keys. New keys are generated
   according to the assigned policy and are rolled automatically in a safe manner.
   No intervention from the zone operator is necessary.

For automatic DNSSEC signing, a :ref:`policy<Policy section>` must
be configured and assigned to the zone. The policy specifies how the zone
is signed (i.e. signing algorithm, key size, key lifetime, signature lifetime,
etc.). If no policy is specified, the default signing parameters are used.

The DNSSEC signing process maintains some metadata which is stored in the
:abbr:`KASP (Key And Signature Policy)` database. This database is backed
by LMDB.

.. WARNING::
  Make sure to set the KASP database permissions correctly. For manual key
  management, the database must be *readable* by the server process. For
  automatic key management, it must be *writeable*. If no HSM is used,
  the database also contains private key material – don't set the permissions
  too weak.

.. _dnssec-manual-key-management:

Manual key management
---------------------

For automatic DNSSEC signing with manual key management, the
:ref:`policy_manual` has to be enabled in the policy::

  policy:
    - id: manual
      manual: on

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: manual

To generate signing keys, use the :doc:`keymgr<man_keymgr>` utility.
For example, we can use Single-Type Signing:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes

And reload the server. The zone will be signed.

To perform a manual rollover of a key, the timing parameters of the key need
to be set. Let's roll the key. Generate a new key, but do not activate
it yet:

.. code-block:: console

  $ keymgr myzone.test. generate algorithm=ECDSAP256SHA256 ksk=yes zsk=yes active=+1d

Take the key ID (or key tag) of the old key and disable it the same time
the new key gets activated:

.. code-block:: console

  $ keymgr myzone.test. set <old_key_id> retire=+2d remove=+3d

Reload the server again. The new key will be published (i.e. the DNSKEY record
will be added into the zone). Remember to update the DS record in the
parent zone to include a reference to the new key. This must happen within one
day (in this case) including a delay required to propagate the new DS to
caches.

.. _dnssec-automatic-zsk-management:

Automatic ZSK management
------------------------

With :ref:`policy_manual` disabled in the assigned policy (the default),
the DNSSEC keys are generated automatically (if they do not already exist)
and are also automatically rolled over according to their configured lifetimes.
The default :ref:`policy_zsk-lifetime` is finite, whereas :ref:`policy_ksk-lifetime`
infinite, meaning no KSK rollovers occur in the following example::

  policy:
    - id: custom_policy
      signing-threads: 4
      algorithm: ECDSAP256SHA256
      zsk-lifetime: 60d

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: custom_policy

After configuring the server, reload the changes:

.. code-block:: console

  $ knotc reload

Check the server logs (regularly) to see whether everything went well.

.. NOTE::
   Enabling automatic key management with already existing keys requires attention:

   - Any key timers set to future timestamps are automatically cleared,
     preventing interference with automatic operation procedures.
   - If the keys are in an inconsistent state (e.g. an unexpected number of keys
     or active keys), it might lead to undefined behavior or, at the very least,
     a halt in key management.

.. _dnssec-automatic-ksk-management:

Automatic KSK management
------------------------

For automatic KSK management, first configure ZSK management as described above,
and use :ref:`submission section <Submission section>` along with several options in
:ref:`policy section <Policy section>`, specifying the desired (finite) lifetime for
KSK and semi-automatic DS submission (see also :ref:`DNSSEC Key states` and
:ref:`DNSSEC Key rollovers`)::

  remote:
    - id: parent_zone_server
      address: 192.168.12.1@53

  submission:
    - id: parent_zone_sbm
      parent: [parent_zone_server]

  policy:
    - id: custom_policy
      signing-threads: 4
      algorithm: ECDSAP256SHA256
      zsk-lifetime: 60d
      ksk-lifetime: 365d
      ksk-submission: parent_zone_sbm

  zone:
    - domain: myzone.test
      dnssec-signing: on
      dnssec-policy: custom_policy

After the initially-generated KSK reaches its lifetime, new KSK is published and after
convenience delay the submission is started. The server publishes CDS and CDNSKEY records
and the user shall propagate them to the parent. The server periodically checks for
DS at the parent zone and when positive, finishes the rollover.

.. NOTE::
   When the initial keys are automatically generated for the first time, the KSK
   is actually in the ``ready`` state, allowing the initial parent DS submission
   to take place automatically.

.. _dnssec-signing:

Zone signing
------------

The signing process consists of the following steps:

#. Processing KASP database events. (e.g. performing a step of a rollover).
#. Updating the DNSKEY records. The whole DNSKEY set in zone apex is replaced
   by the keys from the KASP database. Note that keys added into the zone file
   manually will be removed. To add an extra DNSKEY record into the set, the
   key must be imported into the KASP database (possibly deactivated).
#. Fixing the NSEC or NSEC3 chain.
#. Removing expired signatures, invalid signatures, signatures expiring
   in a short time, and signatures issued by an unknown key.
#. Creating missing signatures. Unless the Single-Type Signing Scheme
   is used, DNSKEY records in a zone apex are signed by KSK keys and
   all other records are signed by ZSK keys.
#. Updating and re-signing SOA record.

The signing is initiated on the following occasions:

- Start of the server
- Zone reload
- Reaching the signature refresh period
- Key set changed due to rollover event
- NSEC3 salt is changed
- Received DDNS update
- Forced zone re-sign via server control interface

On a forced zone re-sign, all signatures in the zone are dropped and recreated.

The ``knotc zone-status`` command can be used to see when the next scheduled
DNSSEC re-sign will happen.

.. _dnssec-on-slave-signing:

On-secondary (on-slave) signing
-------------------------------

It is possible to enable automatic DNSSEC zone signing even on a secondary
server. If enabled, the zone is signed after every AXFR/IXFR transfer
from primary, so that the secondary always serves a signed up-to-date version
of the zone.

It is strongly recommended to block any outside access to the primary
server, so that only the secondary server's signed version of the zone is served.

Enabled on-secondary signing introduces events when the secondary zone changes
while the primary zone remains unchanged, such as a key rollover or
refreshing of RRSIG records, which cause inequality of zone SOA serial
between primary and secondary. The secondary server handles this by saving the
primary's SOA serial in a special variable inside KASP DB and appropriately
modifying AXFR/IXFR queries/answers to keep the communication with
primary server consistent while applying the changes with a different serial.

.. _catalog-zones:

Catalog zones
=============

Catalog zones (:rfc:`9432`) are a concept whereby a list of zones to be configured is maintained
as contents of a separate, special zone. This approach has the benefit of simple
propagation of a zone list to secondary servers, especially when the list is
frequently updated.

Terminology first. *Catalog zone* is a meta-zone which shall not be a part
of the DNS tree, but it contains information about the set of member zones and
is transferable to secondary servers using common AXFR/IXFR techniques.
A *catalog-member zone* (or just *member zone*) is a zone based on
information from the catalog zone and not from configuration file/database.
*Member properties* are some additional information related to each member zone,
also distributed with the catalog zone.

A catalog zone is handled almost in the same way as a regular zone:
It can be configured using all the standard options (but for example
DNSSEC signing is useless as the zone won't be queried by clients), including primary/secondary configuration
and ACLs. A catalog zone is indicated by setting the option
:ref:`zone_catalog-role`. Standard DNS queries to a catalog zone are answered
with REFUSED as though the zone doesn't exist unless there is a matching ACL
rule for action transfer configured.
The name of the catalog zone is arbitrary. It's possible to configure
multiple catalog zones.

.. WARNING::
   Don't choose a name for a catalog zone below a name of any other
   existing zones configured on the server as it would effectively "shadow"
   part of your DNS subtree.

Upon catalog zone (re)load or change, all the PTR records in the format
``unique-id.zones.catalog. 0 IN PTR member.com.`` (but not ``too.deep.zones.catalog.``!)
are processed and member zones created, with zone names taken from the
PTR records' RData, and zone settings taken from the configuration
templates specified by :ref:`zone_catalog-template`.

The owner names of the PTR records shall follow this scheme:

.. code-block:: console

    <unique-id>.zones.<catalog-zone>.

where the mentioned labels shall match:

- *<unique-id>* — Single label that is recommended to be unique among member zones.
- ``zones`` — Required label.
- *<catalog-zone>* — Name of the catalog zone.

Additionally, records in the format
``group.unique-id.zones.catalog. 0 IN TXT "conf-template"``
are processed as a definition of the member's *group* property. The
``unique-id`` must match the one of the PTR record defining the member.
It's required that at most one group is defined for each member. If multiple
groups are defined, one group is picked at random.

All other records and other member properties are ignored. They remain in the catalog
zone, however, and might be for example transferred to a secondary server,
which may interpret catalog zones differently. SOA still needs to be present in
the catalog zone and its serial handled appropriately. An apex NS record must be
present as for any other zone. The version record ``version 0 IN TXT "2"``
is required at the catalog zone apex.

A catalog zone may be modified using any standard means (e.g. AXFR/IXFR, DDNS,
zone file reload). In the case of incremental change, only affected
member zones are reloaded.

The catalog zone must have at least one :ref:`zone_catalog-template`
configured. The configuration for any defined member zone is taken from its
*group* property value, which should match some catalog-template name.
If the *group* property is not defined for a member, is empty, or doesn't match
any of defined catalog-template names, the first catalog-template
(in the order from configuration) is used. Nesting of catalog zones isn't
supported.

Any de-cataloged member zone is purged immediately, including its
zone file, journal, timers, and DNSSEC keys. The zone file is not
deleted if :ref:`zone_zonefile-sync` is set to *-1* for member zones.
Any member zone, whose PTR record's owner has been changed, is purged
immediately if and only if the *<unique-id>* has been changed.

When setting up catalog zones, it might be useful to set
:ref:`database_catalog-db` and :ref:`database_catalog-db-max-size`
to non-default values.

.. NOTE::

   Whenever a catalog zone is updated, the server reloads itself with
   all configured zones, including possibly existing other catalog zones.
   It's similar to calling `knotc zone-reload` (for all zones).
   The consequence is that new zone files might be discovered and reloaded,
   even for zones that do not relate to updated catalog zone.

   Catalog zones never expire automatically, regardless of what is declared
   in the catalog zone SOA. However, a catalog zone can be expired manually
   at any time using `knotc -f zone-purge +expire`.

   Currently, expiration of a catalog zone doesn't have any effect on its
   member zones.

.. WARNING::

   The server does not work well if one member zone appears in two catalog zones
   concurrently. The user is encouraged to avoid this situation whatsoever.
   Thus, there is no way a member zone can be migrated from one catalog
   to another while preserving its metadata. Following steps may be used
   as a workaround:

   * :ref:`Back up<Data and metadata backup>` the member zone's metadata
     (on each server separately).
   * Remove the member zone from the catalog it's a member of.
   * Wait for the catalog zone to be propagated to all servers.
   * Add the member zone to the other catalog.
   * Restore the backed up metadata (on each server separately).

Catalog zones configuration examples
------------------------------------

Below are configuration snippets (e.g. `server` and `log` sections missing)
of very simple catalog zone setups, in order to illustrate the relations
between catalog-related configuration options.

First setup represents a very simple scenario where the primary is
the catalog zone generator and the secondary is the catalog zone consumer.

Primary configuration::

  acl:
    - id: slave_xfr
      address: ...
      action: transfer

  template:
    - id: mmemb
      catalog-role: member
      catalog-zone: catz.
      acl: slave_xfr

  zone:
    - domain: catz.
      catalog-role: generate
      acl: slave_xfr

    - domain: foo.com.
      template: mmemb

    - domain: bar.com.
      template: mmemb

Secondary configuration::

  acl:
    - id: master_notify
      address: ...
      action: notify

  template:
    - id: smemb
      master: master
      acl: master_notify

  zone:
    - domain: catz.
      master: master
      acl: master_notify
      catalog-role: interpret
      catalog-template: smemb

When new zones are added (or removed) to the primary configuration with assigned
`mmemb` template, they will automatically propagate to the secondary
and have the `smemb` template assigned there.

Second example is with a hand-written (or script-generated) catalog zone,
while employing configuration groups::

  catz.                   0       SOA     invalid. invalid. 1625079950 3600 600 2147483646 0
  catz.                   0       NS      invalid.
  version.catz.           0       TXT     "2"
  nj2xg5bnmz2w4ltd.zones.catz.       0       PTR     just-fun.com.
  group.nj2xg5bnmz2w4ltd.zones.catz. 0       TXT     unsigned
  nvxxezjnmz2w4ltd.zones.catz.       0       PTR     more-fun.com.
  group.nvxxezjnmz2w4ltd.zones.catz. 0       TXT     unsigned
  nfwxa33sorqw45bo.zones.catz.       0       PTR     important.com.
  group.nfwxa33sorqw45bo.zones.catz. 0       TXT     signed
  mjqw42zomnxw2lq0.zones.catz.       0       PTR     bank.com.
  group.mjqw42zomnxw2lq0.zones.catz. 0       TXT     signed

And the server in this case is configured to distinguish the groups by applying
different templates::

  template:
    - id: unsigned
      ...

    - id: signed
      dnssec-signing: on
      dnssec-policy: ...
      ...

  zone:
    - domain: catz.
      file: ...
      catalog-role: interpret
      catalog-template: [ unsigned, signed ]

.. _DNS_over_QUIC:

DNS over QUIC
=============

QUIC is a low-latency, encrypted, internet transport protocol.
Knot DNS supports DNS over QUIC (DoQ) (:rfc:`9250`), including zone transfers (XoQ).
By default, the UDP port `853` is used for DNS over QUIC.

To use QUIC, a server :ref:`private key<server_key-file>` and a :ref:`certificate<server_cert-file>`
must be available. If no key is configured, the server automatically generates one
with a self-signed temporary certificate. The key is stored in the KASP database
directory for persistence across restarts.

In order to listen for incoming requests over QUIC, at least one :ref:`interface<server_listen-quic>`
or :ref:`XDP interface<xdp_quic>` must be configured.

An example of configuration of listening for DNS over QUIC on the loopback interface:

.. code-block:: console

  server:
    listen-quic: ::1

When the server is started, it logs some interface details and public key pin
of the used certificate:

.. code-block:: console

  ... info: binding to QUIC interface ::1@853
  ... info: QUIC/TLS, certificate public key 0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=

.. TIP::

  The public key pin, which isn't secret, can also be displayed via:

  .. code-block:: console

    $ knotc status cert-key
    0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=

  Or from the keyfile via:

  .. code-block:: console

    $ certtool --infile=quic_key.pem -k | grep pin-sha256
         pin-sha256:0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=

Using :doc:`kdig<man_kdig>` we can verify that the server responds over QUIC:

.. code-block:: console

  $ kdig @::1 ch txt version.server +quic
  ;; QUIC session (QUICv1)-(TLS1.3)-(ECDHE-X25519)-(EdDSA-Ed25519)-(AES-256-GCM)
  ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 0
  ;; Flags: qr rd; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 1

  ;; EDNS PSEUDOSECTION:
  ;; Version: 0; flags: ; UDP size: 1232 B; ext-rcode: NOERROR
  ;; PADDING: 370 B

  ;; QUESTION SECTION:
  ;; version.server.     		CH	TXT

  ;; ANSWER SECTION:
  version.server.     	0	CH	TXT	"Knot DNS 3.4.0"

  ;; Received 468 B
  ;; Time 2024-06-21 08:30:12 CEST
  ;; From ::1@853(QUIC) in 1.1 ms

In this case, :rfc:`opportunistic authentication<9103#section-9.3.1>` was
used, which doesn't guarantee that the client communicates with the genuine server
and vice versa. For :rfc:`strict authentication<9103#section-9.3.2>`
of the server, we can enforce certificate key pin check by specifying it
(enabled debug mode for details):

.. code-block:: console

  $ kdig @::1 ch txt version.server +tls-pin=0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw= +quic -d
  ;; DEBUG: Querying for owner(version.server.), class(3), type(16), server(::1), port(853), protocol(UDP)
  ;; DEBUG: TLS, received certificate hierarchy:
  ;; DEBUG:  #1, CN=tester
  ;; DEBUG:      SHA-256 PIN: 0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=, MATCH
  ;; DEBUG: TLS, skipping certificate verification
  ;; QUIC session (QUICv1)-(TLS1.3)-(ECDHE-X25519)-(EdDSA-Ed25519)-(AES-256-GCM)
  ...

We see that a server certificate key matches the specified pin. Another possibility
is to use certificate chain validation if a suitable certificate is configured
on the server.

Zone transfers
--------------

For outgoing requests (e.g. NOTIFY and refresh), Knot DNS utilizes
:rfc:`session resumption<9250#section-5.5.3>`, which speeds up QUIC connection
establishment.

Here are a few examples of zone transfer configurations using various
:rfc:`authentication mechanisms<9103#section-9>`:

Opportunistic authentication:
.............................

Primary and secondary can authenticate using TSIG. Fallback to clear-text DNS
isn't supported.

.. panels::

  Primary:

  .. code-block:: console

    server:
        listen-quic: ::1
        automatic-acl: on

    key:
      - id: xfr_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: secondary
        address: ::2
        key: xfr_key  # TSIG for secondary authentication
        quic: on

    zone:
      - domain: example.com
        notify: secondary

  ---

  Secondary:

  .. code-block:: console

    server:
        listen-quic: ::2
        automatic-acl: on

    key:
      - id: xfr_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: primary
        address: ::1
        key: xfr_key  # TSIG for primary authentication
        quic: on

    zone:
      - domain: example.com
        master: primary

Strict authentication:
......................

Note that the automatic ACL doesn't work in this case due to asymmetrical
configuration. The secondary can authenticate using TSIG.

With PIN checks:

.. panels::

  Primary:

  .. code-block:: console

    server:
        listen-quic: ::1

    key:
      - id: secondary_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: secondary
        address: ::2
        quic: on

    acl:
      - id: secondary_xfr
        address: ::2
        key: secondary_key  # TSIG for secondary authentication
        action: transfer

    zone:
      - domain: example.com
        notify: secondary
        acl: secondary_xfr

  ---

  Secondary:

  .. code-block:: console

    server:
        listen-quic: ::2

    key:
      - id: secondary_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: primary
        address: ::1
        key: secondary_key  # TSIG for secondary authentication
        quic: on

    acl:
      - id: primary_notify
        address: ::1
        cert-key: 0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=
        action: notify

    zone:
      - domain: example.com
        master: primary
        acl: primary_notify

With CA and hostname checks:

.. panels::

  Primary

  .. code-block:: console

    server:
        listen-quic: ::1
        cert-file: primary-cert.pem
        key-file: primary-key.pem

    key:
      - id: secondary_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: secondary
        address: ::2
        quic: on

    acl:
      - id: secondary_xfr
        address: ::2
        key: secondary_key  # TSIG for secondary authentication
        action: transfer

    zone:
      - domain: example.com
        notify: secondary
        acl: secondary_xfr

  ---

  Secondary:

  .. code-block:: console

    server:
        listen-quic: ::2
        ca-file: ca-cert.pem

    key:
      - id: secondary_key
        algorithm: hmac-sha256
        secret: S059OFJv1SCDdR2P6JKENgWaM409iq2X44igcJdERhc=

    remote:
      - id: primary
        address: ::1
        key: secondary_key  # TSIG for secondary authentication
        quic: on

    acl:
      - id: primary_notify
        address: ::1
        cert-hostname: "Primary Knot"
        action: notify

    zone:
      - domain: example.com
        master: primary
        acl: primary_notify

Mutual authentication:
......................

The :rfc:`mutual authentication<9103#section-9.3.3>` guarantees authentication
for both the primary and the secondary. In this case, TSIG would be redundant.
This mode is recommended if possible.

With PIN checks:

.. panels::

  Primary:

  .. code-block:: console

    server:
        listen-quic: ::1
        automatic-acl: on

    remote:
      - id: secondary
        address: ::2
        quic: on
        cert-key: PXqv7/lXn6N7scg/KJWvfU/TEPe5BoIUHQGRLMPr6YQ=

    zone:
      - domain: example.com
        notify: secondary

  ---

  Secondary:

  .. code-block:: console

    server:
        listen-quic: ::2
        automatic-acl: on

    remote:
      - id: primary
        address: ::1
        quic: on
        cert-key: 0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=

    zone:
      - domain: example.com
        master: primary

With CA and hostname checks:

.. panels::

  Primary:

  .. code-block:: console

    server:
        listen-quic: ::1
        ca-file: ca-cert.pem
        cert-file: primary-cert.pem
        key-file: primary-key.pem
        automatic-acl: on

    remote:
      - id: secondary
        address: ::2
        quic: on
        cert-hostname: "Secondary Knot"

    zone:
      - domain: example.com
        notify: secondary

  ---

  Secondary:

  .. code-block:: console

    server:
        listen-quic: ::2
        ca-file: ca-cert.pem
        cert-file: secondary-cert.pem
        key-file: secondary-key.pem
        automatic-acl: on

    remote:
      - id: primary
        address: ::1
        quic: on
        cert-hostname: "Primary Knot"

    zone:
      - domain: example.com
        master: primary

.. TIP::

  Using GnuTLS certtool you can generate a CA certificate with its private key:

  .. code-block:: console

    $ certtool --generate-privkey --key-type ed25519 --outfile ca-key.pem
    $ echo -e "cn = \"My Example CA\"\nca\ncert_signing_key\nexpiration_days = 3650" >ca-template.info
    $ certtool --generate-self-signed --load-privkey ca-key.pem \
               --template ca-template.info --outfile ca-cert.pem

  Then create certificates signed with this CA like so:

  .. code-block:: console

    $ CERT_NAME="primary"
    $ certtool --generate-privkey --key-type ed25519 --outfile ${CERT_NAME}-key.pem
    $ echo -e "dns_name = \"${CERT_NAME} server\"\nexpiration_days = 365" >${CERT_NAME}-template.info
    $ certtool --generate-certificate --load-privkey ${CERT_NAME}-key.pem \
               --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
               --template ${CERT_NAME}-template.info --outfile ${CERT_NAME}-cert.pem

  If you want to use a wildcard DNSName in your certificate, beware that
  GnuTLS, which is the TLS backend for Knot DNS, **will not verify** wildcard
  names directly under TLDs (like ``*.example``).

  To see a server's TLS hostnames:

  .. code-block:: console

    $ kdig @1.1.1.1 +tls -dd
    ;; DEBUG: Querying for owner(.), class(1), type(2), server(1.1.1.1), port(853), protocol(TCP)
    ;; DEBUG: TLS, received certificate hierarchy:
    ;; DEBUG:  #1, CN=cloudflare-dns.com,O=Cloudflare\, Inc.,L=San Francisco,ST=California,C=US
    ;; DEBUG:      Subject Alternative Name:
    ;; DEBUG:        DNSname: cloudflare-dns.com
    ;; DEBUG:        DNSname: *.cloudflare-dns.com
    ;; DEBUG:        DNSname: one.one.one.one
    [...]

  Knot DNS will only verify hostnames under the *Subject Alternative Name*
  extension in compliance with :rfc:`8310#section-8.1`.

.. NOTE::

  Certificate validation by CA and hostname is more computationally expensive
  than by PIN, but PIN checking has the disadvantage of relying on constantness
  of the public key.

.. _DNS_over_TLS:

DNS over TLS
============

TLS is an encrypted internet transport protocol.
Knot DNS supports DNS over TLS (DoT) (:rfc:`7858`), including zone transfers (XoT).
By default, the TCP port `853` is used for DNS over TLS.

There are the same requirements for TLS key and certificate as for :ref:`DNS_over_QUIC`.

In order to listen for incoming requests over TLS, :ref:`interface<server_listen-tls>`
must be configured.

An example of configuration of listening for DNS over TLS on the loopback interface:

.. code-block:: console

  server:
    listen-tls: ::1

When the server is started, it logs some interface details and public key pin
of the used certificate:

.. code-block:: console

  ... info: binding to TLS interface ::1@853
  ... info: QUIC/TLS, certificate public key 0xtdayWpnJh4Py8goi8cei/gXGD4kJQ+HEqcxS++DBw=

Using :doc:`kdig<man_kdig>` we can verify that the server responds over TLS:

.. code-block:: console

  $ kdig @::1 ch txt version.server +tls
  ;; TLS session (TLS1.3)-(ECDHE-X25519)-(EdDSA-Ed25519)-(AES-256-GCM)
  ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 0
  ;; Flags: qr rd; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 1

  ;; EDNS PSEUDOSECTION:
  ;; Version: 0; flags: ; UDP size: 1232 B; ext-rcode: NOERROR
  ;; PADDING: 370 B

  ;; QUESTION SECTION:
  ;; version.server.     		CH	TXT

  ;; ANSWER SECTION:
  version.server.     	0	CH	TXT	"Knot DNS 3.4.0"

  ;; Received 468 B
  ;; Time 2024-06-21 08:31:13 CEST
  ;; From ::1@853(TLS) in 9.1 ms

Zone transfer configuration and authentication profiles are almost identical
to :ref:`DNS_over_QUIC`, with the only difference being the enabling of
:ref:`remote_tls` for the corresponding remotes.

.. _query-modules:

Query modules
=============

Knot DNS supports configurable query modules that can alter the way
queries are processed. Each query requires a finite number of steps to
be resolved. We call this set of steps a *query plan*, an abstraction
that groups these steps into several stages.

* Before-query processing
* Answer, Authority, Additional records packet sections processing
* After-query processing

For example, processing an Internet-class query needs to find an
answer. Then based on the previous state, it may also append an
authority SOA or provide additional records. Each of these actions
represents a 'processing step'. Now, if a query module is loaded for a
zone, it is provided with an implicit query plan which can be extended
by the module or even changed altogether.

A module is active if its name, which includes the ``mod-`` prefix, is assigned
to the zone/template :ref:`zone_module` option or to the ``default`` template
:ref:`template_global-module` option if activating for all queries.
If the module is configurable, a corresponding module section with
an identifier must be created and then referenced in the form of
``module_name/module_id``. See :ref:`Modules` for the list of available modules.

The same module can be specified multiple times, such as a global module and
a per-zone module, or with different configurations. However, not all modules
are intended for this, for example, mod-cookies! Global modules are executed
before per-zone modules.

.. NOTE::
   Query modules are processed in the order they are specified in the
   zone/template configuration. In most cases, the recommended order is::

      mod-synthrecord, mod-onlinesign, mod-cookies, mod-rrl, mod-dnstap, mod-stats

Performance Tuning
==================

Numbers of Workers
------------------

There are three types of workers ready for parallel execution of performance-oriented tasks:
UDP workers, TCP workers, and Background workers. The first two types handle all network requests
via the UDP and TCP protocol (respectively) and do the response jobs for common
queries. Background workers process changes to the zone.

By default, Knot determines a well-fitting number of workers based on the number of CPU cores.
The user can specify the number of workers for each type with configuration/server section:
:ref:`server_udp-workers`, :ref:`server_tcp-workers`, :ref:`server_background-workers`.

An indication of when to increase the number of workers is when the server is lagging behind
expected performance, while CPU usage remains low. This is usually due to waiting for network
or I/O response during the operation. It may be caused by Knot design not fitting the use-case well.
The user should try increasing the number of workers (of the related type) slightly above 100 and if
the performance improves, decide a further, exact setting.

Number of available file descriptors
------------------------------------

A name server configured for a large number of zones (hundreds or more) needs enough file descriptors
available for zone transfers and zone file updates, which default OS settings often don't provide.
It's necessary to check with the OS configuration and documentation and ensure the number of file
descriptors (sometimes called a number of concurrently open files) effective for the knotd process
is set suitably high. The number of concurrently open incoming TCP connections must be taken into
account too. In other words, the required setting is affected by the :ref:`server_tcp-max-clients`
setting.

Sysctl and NIC optimizations
----------------------------

There are several recommendations based on Knot developers' experience with their specific HW and SW
(mainstream Intel-based servers, Debian-based GNU/Linux distribution). They may improve or impact
performance in common use cases.

If your NIC driver allows it (see /proc/interrupts for hint), set CPU affinity (/proc/irq/$IRQ/smp_affinity)
manually so that each NIC channel is served by unique CPU core(s). You must turn off irqbalance service
in advance to avoid configuration override.

Configure sysctl as follows: ::

    socket_bufsize=1048576
    busy_latency=0
    backlog=40000
    optmem_max=20480

    net.core.wmem_max     = $socket_bufsize
    net.core.wmem_default = $socket_bufsize
    net.core.rmem_max     = $socket_bufsize
    net.core.rmem_default = $socket_bufsize
    net.core.busy_read = $busy_latency
    net.core.busy_poll = $busy_latency
    net.core.netdev_max_backlog = $backlog
    net.core.optmem_max = $optmem_max

Disable huge pages.

Configure your CPU to "performance" mode. This can be achieved depending on architecture, e.g. in BIOS,
or e.g. configuring /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor to "performance".

Tune your NIC device with ethtool: ::

    ethtool -A $dev autoneg off rx off tx off
    ethtool -K $dev tso off gro off ufo off
    ethtool -G $dev rx 4096 tx 4096
    ethtool -C $dev rx-usecs 75
    ethtool -C $dev tx-usecs 75
    ethtool -N $dev rx-flow-hash udp4 sdfn
    ethtool -N $dev rx-flow-hash udp6 sdfn

On FreeBSD you can just: ::

    ifconfig ${dev} -rxcsum -txcsum -lro -tso

Knot developers are open to hear about users' further suggestions about network devices tuning/optimization.
