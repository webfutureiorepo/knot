/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "contrib/sockaddr.h"
#include "libknot/errcode.h"

static void test_sockaddr_is_any(void)
{
	struct sockaddr_storage invalid = { 0 };
	ok(!sockaddr_is_any(&invalid), "sockaddr_is_any: invalid");

	struct sockaddr_storage path = { 0 };
	path.ss_family = AF_UNIX;
	ok(!sockaddr_is_any(&path), "sockaddr_is_any: unix");

	struct sockaddr_storage ipv4_local = { 0 };
	sockaddr_set(&ipv4_local, AF_INET, "127.0.0.1", 0);
	ok(!sockaddr_is_any(&ipv4_local), "sockaddr_is_any: IPv4 local");

	struct sockaddr_storage ipv4_any = { 0 };
	sockaddr_set(&ipv4_any, AF_INET, "0.0.0.0", 0);
	ok(sockaddr_is_any(&ipv4_any), "sockaddr_is_any: IPv4 any");

	struct sockaddr_storage ipv6_local = { 0 };
	sockaddr_set(&ipv6_local, AF_INET6, "::1", 0);
	ok(!sockaddr_is_any(&ipv6_local), "sockaddr_is_any: IPv6 local");

	struct sockaddr_storage ipv6_any = { 0 };
	sockaddr_set(&ipv6_any, AF_INET6, "::", 0);
	ok(sockaddr_is_any(&ipv6_any), "sockaddr_is_any: IPv6 any");
}

static void check_sockaddr_set(struct sockaddr_storage *ss, int family,
                               const char *straddr, int port)
{
	int ret = sockaddr_set(ss, family, straddr, port);
	is_int(KNOT_EOK, ret, "set address '%s'", straddr);
}

static void test_net_match(void)
{
	int ret;
	struct sockaddr_storage t = { 0 };

	// 127 dec ~ 01111111 bin
	// 170 dec ~ 10101010 bin
	struct sockaddr_storage ref4 = { 0 };
	check_sockaddr_set(&ref4, AF_INET, "127.170.170.127", 0);

	// 7F hex ~ 01111111 bin
	// AA hex ~ 10101010 bin
	struct sockaddr_storage ref6 = { 0 };
	check_sockaddr_set(&ref6, AF_INET6, "7FAA::AA7F", 0);

	ret = sockaddr_net_match(&ref4, &ref6, 32);
	ok(ret == false, "match: family mismatch");

	ret = sockaddr_net_match(NULL, &ref4, 32);
	ok(ret == false, "match: NULL first parameter");
	ret = sockaddr_net_match(&ref4, NULL, 32);
	ok(ret == false, "match: NULL second parameter");

	ret = sockaddr_net_match(&ref4, &ref4, -1);
	ok(ret == true, "match: ipv4 - identity, auto full prefix");
	ret = sockaddr_net_match(&ref4, &ref4, 31);
	ok(ret == true, "match: ipv4 - identity, subnet");
	ret = sockaddr_net_match(&ref4, &ref4, 32);
	ok(ret == true, "match: ipv4 - identity, full prefix");
	ret = sockaddr_net_match(&ref4, &ref4, 33);
	ok(ret == true, "match: ipv4 - identity, prefix overflow");

	ret = sockaddr_net_match(&ref6, &ref6, -1);
	ok(ret == true, "match: ipv6 - identity, auto full prefix");
	ret = sockaddr_net_match(&ref6, &ref6, 127);
	ok(ret == true, "match: ipv6 - identity, subnet");
	ret = sockaddr_net_match(&ref6, &ref6, 128);
	ok(ret == true, "match: ipv6 - identity, full prefix");
	ret = sockaddr_net_match(&ref6, &ref6, 129);
	ok(ret == true, "match: ipv6 - identity, prefix overflow");

	// 124 dec ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET, "124.0.0.0", 0);
	ret = sockaddr_net_match(&t, &ref4, 5);
	ok(ret == true, "match: ipv4 - first byte, shorter prefix");
	ret = sockaddr_net_match(&t, &ref4, 6);
	ok(ret == true, "match: ipv4 - first byte, precise prefix");
	ret = sockaddr_net_match(&t, &ref4, 7);
	ok(ret == false, "match: ipv4 - first byte, not match");

	check_sockaddr_set(&t, AF_INET, "127.170.170.124", 0);
	ret = sockaddr_net_match(&t, &ref4, 29);
	ok(ret == true, "match: ipv4 - last byte, shorter prefix");
	ret = sockaddr_net_match(&t, &ref4, 30);
	ok(ret == true, "match: ipv4 - last byte, precise prefix");
	ret = sockaddr_net_match(&t, &ref4, 31);
	ok(ret == false, "match: ipv4 - last byte, not match");

	// 7C hex ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET6, "7CAA::", 0);
	ret = sockaddr_net_match(&t, &ref6, 5);
	ok(ret == true, "match: ipv6 - first byte, shorter prefix");
	ret = sockaddr_net_match(&t, &ref6, 6);
	ok(ret == true, "match: ipv6 - first byte, precise prefix");
	ret = sockaddr_net_match(&t, &ref6, 7);
	ok(ret == false, "match: ipv6 - first byte, not match");

	check_sockaddr_set(&t, AF_INET6, "7FAA::AA7C", 0);
	ret = sockaddr_net_match(&t, &ref6, 125);
	ok(ret == true, "match: ipv6 - last byte, shorter prefix");
	ret = sockaddr_net_match(&t, &ref6, 126);
	ok(ret == true, "match: ipv6 - last byte, precise prefix");
	ret = sockaddr_net_match(&t, &ref6, 127);
	ok(ret == false, "match: ipv6 - last byte, not match");

	// UNIX socket path tests

	struct sockaddr_storage ref_un = { 0 };
	check_sockaddr_set(&ref_un, AF_UNIX, "/tmp/knot.listen", 0);

	check_sockaddr_set(&t, AF_UNIX, "/tmp/knot.listen", 0);
	ret = sockaddr_net_match(&t, &ref_un, 0);
	ok(ret == true, "match: UNIX, match");

	check_sockaddr_set(&t, AF_UNIX, "/tmp/knot.liste", 0);
	ret = sockaddr_net_match(&t, &ref_un, 0);
	ok(ret == false, "match: UNIX, shorter, not match");

	check_sockaddr_set(&t, AF_UNIX, "/tmp/knot.listen.", 0);
	ret = sockaddr_net_match(&t, &ref_un, 0);
	ok(ret == false, "match: UNIX, longer, not match");

	check_sockaddr_set(&t, AF_UNIX, "1234567890123456789012345678901234567890", 0);
	ret = sockaddr_net_match(&t, &ref_un, 0);
	ok(ret == false, "match: UNIX, longer than max for sockaddr_t, not match");
}

static void test_range_match(void)
{
	bool ret;
	struct sockaddr_storage t = { 0 };
	struct sockaddr_storage min = { 0 };
	struct sockaddr_storage max = { 0 };

	// IPv4 tests.

	check_sockaddr_set(&min, AF_INET, "0.0.0.0", 0);
	check_sockaddr_set(&max, AF_INET, "255.255.255.255", 0);

	check_sockaddr_set(&t, AF_INET, "0.0.0.0", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 max range - minimum");
	check_sockaddr_set(&t, AF_INET, "255.255.255.255", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 max range - maximum");

	check_sockaddr_set(&min, AF_INET, "1.13.113.213", 0);
	check_sockaddr_set(&max, AF_INET, "2.24.124.224", 0);

	check_sockaddr_set(&t, AF_INET, "1.12.113.213", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.212", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.213", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - minimum");
	check_sockaddr_set(&t, AF_INET, "1.13.213.213", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - middle");
	check_sockaddr_set(&t, AF_INET, "2.24.124.224", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - max");
	check_sockaddr_set(&t, AF_INET, "2.24.124.225", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET, "2.25.124.225", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative far max");

	// IPv6 tests.

	check_sockaddr_set(&min, AF_INET6, "::0", 0);
	check_sockaddr_set(&max, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);

	check_sockaddr_set(&t, AF_INET6, "::0", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 max range - minimum");
	check_sockaddr_set(&t, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 max range - maximum");

	check_sockaddr_set(&min, AF_INET6, "1:13::ABCD:200B", 0);
	check_sockaddr_set(&max, AF_INET6, "2:A24::124:224", 0);

	check_sockaddr_set(&t, AF_INET6, "1:12::BCD:2000", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200A", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200B", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - minimum");
	check_sockaddr_set(&t, AF_INET6, "1:13:0:12:34:0:ABCD:200B", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - middle");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:224", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - max");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:225", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET6, "2:FA24::4:24", 0);
	ret = sockaddr_range_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative far max");

	// UNIX socket path tests

	check_sockaddr_set(&t, AF_UNIX, "/tmp/knot.listen", 0);
	ret = sockaddr_range_match(&t, &t, &t);
	ok(ret == false, "match: range not supported for UNIX");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("sockaddr_is_any");
	test_sockaddr_is_any();

	diag("sockaddr_net_match");
	test_net_match();

	diag("sockaddr_range_match");
	test_range_match();

	return 0;
}
