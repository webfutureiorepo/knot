/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "contrib/dnstap/convert.h"
#include "contrib/dnstap/dnstap.pb-c.h"
#include "libknot/probe/data.h"

/*!
 * \brief Translation between real and Dnstap value.
 */
typedef struct mapping {
	int real;
	int dnstap;
} mapping_t;

/*!
 * \brief Mapping for network family.
 */
static const mapping_t SOCKET_FAMILY_MAPPING[] = {
	{ AF_INET,  DNSTAP__SOCKET_FAMILY__INET },
	{ AF_INET6, DNSTAP__SOCKET_FAMILY__INET6 },
	{ 0 }
};

/*!
 * \brief Mapping from network protocol.
 */
static const mapping_t SOCKET_PROTOCOL_MAPPING[] = {
	{ KNOT_PROBE_PROTO_UDP,   DNSTAP__SOCKET_PROTOCOL__UDP },
	{ KNOT_PROBE_PROTO_TCP,   DNSTAP__SOCKET_PROTOCOL__TCP },
	{ KNOT_PROBE_PROTO_TLS,   DNSTAP__SOCKET_PROTOCOL__DOT },
	{ KNOT_PROBE_PROTO_HTTPS, DNSTAP__SOCKET_PROTOCOL__DOH },
	{ KNOT_PROBE_PROTO_QUIC,  DNSTAP__SOCKET_PROTOCOL__DOQ },
	{ 0 }
};

/*!
 * \brief Get Dnstap value for a given real value.
 */
static int encode(const mapping_t *mapping, int real)
{
	for (const mapping_t *m = mapping; m->dnstap != 0; m += 1) {
		if (m->real == real) {
			return m->dnstap;
		}
	}

	return 0;
}

/*!
 * \brief Get real value for a given Dnstap value.
 */
static int decode(const mapping_t *mapping, int dnstap)
{
	for (const mapping_t *m = mapping; m->dnstap != 0; m += 1) {
		if (m->dnstap == dnstap) {
			return m->real;
		}
	}

	return 0;
}

/* -- public API ----------------------------------------------------------- */

Dnstap__SocketFamily dt_family_encode(int family)
{
	return encode(SOCKET_FAMILY_MAPPING, family);
}

int dt_family_decode(Dnstap__SocketFamily dnstap_family)
{
	return decode(SOCKET_FAMILY_MAPPING, dnstap_family);
}

Dnstap__SocketProtocol dt_protocol_encode(int protocol)
{
	return encode(SOCKET_PROTOCOL_MAPPING, protocol);
}

int dt_protocol_decode(Dnstap__SocketProtocol dnstap_protocol)
{
	return decode(SOCKET_PROTOCOL_MAPPING, dnstap_protocol);
}

bool dt_message_type_is_query(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
		return true;
	default:
		return false;
	}
}

bool dt_message_type_is_response(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		return true;
	default:
		return false;
	}
}

bool dt_message_role_is_initiator(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
		return false;
	default:
		return true;
	}
}
