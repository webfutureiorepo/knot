/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>

#include "libknot/yparser/yptrafo.h"
#include "libknot/attribute.h"
#include "libknot/consts.h"
#include "libknot/dname.h"
#include "contrib/base64.h"
#include "contrib/ctype.h"
#include "contrib/musl/inet_ntop.h"
#include "contrib/sockaddr.h"
#include "contrib/wire_ctx.h"

enum {
	UNIT_BYTE  = 'B',
	UNIT_KILO  = 'K',
	UNIT_MEGA  = 'M',
	UNIT_GIGA  = 'G',
	UNIT_SEC   = 's',
	UNIT_MIN   = 'm',
	UNIT_HOUR  = 'h',
	UNIT_DAY   = 'd',
	UNIT_WEEK  = 'w',
	UNIT_MONTH = 'M',
	UNIT_YEAR  = 'y',
};

enum {
	MULTI_BYTE  = 1,
	MULTI_KILO  = 1024,
	MULTI_MEGA  = 1024 * 1024,
	MULTI_GIGA  = 1024 * 1024 * 1024,
	MULTI_SEC   = 1,
	MULTI_MIN   = 60,
	MULTI_HOUR  = 3600,
	MULTI_DAY   = 24 * 3600,
	MULTI_WEEK  = MULTI_DAY * 7,
	MULTI_MONTH = MULTI_DAY * 30,
	MULTI_YEAR  = MULTI_DAY * 365,
};

// See also conf_addr_range() if changing.
enum {
	ADDR_TYPE_UNIX           = 0,
	ADDR_TYPE_IPV4           = 4,
	ADDR_TYPE_IPV6           = 6,
	ADDR_TYPE_IPV6_LINKLOCAL = 7,
};

static bool is_addr_unix(uint8_t type)
{
	return type == ADDR_TYPE_UNIX;
}

static bool is_addr_ipv4(uint8_t type)
{
	return type == ADDR_TYPE_IPV4;
}

static bool is_addr_ipv6(uint8_t type)
{
	return type == ADDR_TYPE_IPV6;
}

static inline bool is_addr_ipv6_linklocal(uint8_t type)
{
	return type == ADDR_TYPE_IPV6_LINKLOCAL;
}

static bool is_ip_addr(uint8_t type)
{
	return is_addr_ipv4(type) || is_addr_ipv6(type) || is_addr_ipv6_linklocal(type);
}

static wire_ctx_t copy_in(
	wire_ctx_t *in,
	size_t in_len,
	char *buf,
	size_t buf_len)
{
	wire_ctx_t ctx = wire_ctx_init((uint8_t *)buf, buf_len);
	wire_ctx_write(&ctx, in->position, in_len);
	wire_ctx_skip(in, in_len);
	// Write the terminator.
	wire_ctx_write_u8(&ctx, '\0');
	wire_ctx_skip(&ctx, -1);
	return ctx;
}

_public_
int yp_str_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	wire_ctx_write(out, in->position, YP_LEN);
	wire_ctx_skip(in, YP_LEN);
	// Write string terminator.
	wire_ctx_write_u8(out, '\0');

	YP_CHECK_RET;
}

_public_
int yp_str_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	size_t len = strlen((char *)in->position) + 1;

	wire_ctx_write(out, in->position, len);
	wire_ctx_skip(in, len);
	// Set the terminator as a current position.
	wire_ctx_skip(out, -1);

	YP_CHECK_RET;
}

_public_
int yp_bool_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	if (strncasecmp((char *)in->position, "on",   YP_LEN) == 0 ||
	    strncasecmp((char *)in->position, "true", YP_LEN) == 0) {
		wire_ctx_write_u8(out, 1);
	} else if (strncasecmp((char *)in->position, "off",   YP_LEN) == 0 ||
	           strncasecmp((char *)in->position, "false", YP_LEN) == 0) {
		wire_ctx_write_u8(out, 0);
	} else {
		return KNOT_EINVAL;
	}

	wire_ctx_skip(in, YP_LEN);

	YP_CHECK_RET;
}

_public_
int yp_bool_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	const char *value;

	switch (wire_ctx_read_u8(in)) {
	case 0:
		value = "off";
		break;
	case 1:
		value = "on";
		break;
	default:
		return KNOT_EINVAL;
	}

	int ret = snprintf((char *)out->position, wire_ctx_available(out), "%s",
	                   value);
	if (ret <= 0 || ret >= wire_ctx_available(out)) {
		return KNOT_ESPACE;
	}
	wire_ctx_skip(out, ret);

	YP_CHECK_RET;
}

static int remove_unit(
	int64_t *number,
	char unit,
	yp_style_t style)
{
	int64_t multiplier = 1;

	// Get the multiplier for the unit.
	if (style & YP_SSIZE) {
		switch (unit) {
		case UNIT_BYTE:
			multiplier = MULTI_BYTE;
			break;
		case UNIT_KILO:
			multiplier = MULTI_KILO;
			break;
		case UNIT_MEGA:
			multiplier = MULTI_MEGA;
			break;
		case UNIT_GIGA:
			multiplier = MULTI_GIGA;
			break;
		default:
			return KNOT_EINVAL;
		}
	} else if (style & YP_STIME) {
		switch (unit) {
		case UNIT_SEC:
			multiplier = MULTI_SEC;
			break;
		case UNIT_MIN:
			multiplier = MULTI_MIN;
			break;
		case UNIT_HOUR:
			multiplier = MULTI_HOUR;
			break;
		case UNIT_DAY:
			multiplier = MULTI_DAY;
			break;
		case UNIT_WEEK:
			multiplier = MULTI_WEEK;
			break;
		case UNIT_MONTH:
			multiplier = MULTI_MONTH;
			break;
		case UNIT_YEAR:
			multiplier = MULTI_YEAR;
			break;
		default:
			return KNOT_EINVAL;
		}
	} else {
		return KNOT_EINVAL;
	}

	// Check for possible number overflow.
	if (INT64_MAX / multiplier < (*number >= 0 ? *number : -*number)) {
		return KNOT_ERANGE;
	}

	*number *= multiplier;

	return KNOT_EOK;
}

_public_
int yp_int_to_bin(
	YP_TXT_BIN_PARAMS,
	int64_t min,
	int64_t max,
	yp_style_t style)
{
	YP_CHECK_PARAMS_BIN;

	// Copy input string to the buffer to limit strtoll overread.
	char buf[32];
	wire_ctx_t buf_ctx = copy_in(in, YP_LEN, buf, sizeof(buf));
	if (buf_ctx.error != KNOT_EOK) {
		return buf_ctx.error;
	}

	// Parse the number.
	char *end;
	errno = 0;
	int64_t number = strtoll(buf, &end, 10);

	// Check for number overflow.
	if (errno == ERANGE && (number == LLONG_MAX || number == LLONG_MIN)) {
		return KNOT_ERANGE;
	}
	// Check if the whole string is invalid.
	if ((errno != 0 && number == 0) || end == buf) {
		return KNOT_EINVAL;
	}
	// Check the rest of the string for a unit.
	if (*end != '\0') {
		// Check just for one-char rest.
		if (*(end + 1) != '\0') {
			return KNOT_EINVAL;
		}

		// Try to apply a unit on the number.
		int ret = remove_unit(&number, *end, style);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Check for the result number overflow.
	if (number < min || number > max) {
		return KNOT_ERANGE;
	}

	// Write the result.
	wire_ctx_write_u64(out, number);

	YP_CHECK_RET;
}

static void add_unit(
	int64_t *number,
	char *unit,
	yp_style_t style)
{
	int64_t multiplier = 1;
	char basic_unit = '\0';
	char new_unit = '\0';

	// Get the multiplier for the unit.
	if (style & YP_SSIZE) {
		basic_unit = UNIT_BYTE;

		if (*number < MULTI_KILO) {
			multiplier = MULTI_BYTE;
			new_unit = UNIT_BYTE;
		} else if (*number < MULTI_MEGA) {
			multiplier = MULTI_KILO;
			new_unit = UNIT_KILO;
		} else if (*number < MULTI_GIGA) {
			multiplier = MULTI_MEGA;
			new_unit = UNIT_MEGA;
		} else {
			multiplier = MULTI_GIGA;
			new_unit = UNIT_GIGA;
		}
	} else if (style & YP_STIME) {
		basic_unit = UNIT_SEC;

		if (*number < MULTI_MIN) {
			multiplier = MULTI_SEC;
			new_unit = UNIT_SEC;
		} else if (*number < MULTI_HOUR) {
			multiplier = MULTI_MIN;
			new_unit = UNIT_MIN;
		} else if (*number < MULTI_DAY) {
			multiplier = MULTI_HOUR;
			new_unit = UNIT_HOUR;
		} else if (*number < MULTI_WEEK) {
			multiplier = MULTI_DAY;
			new_unit = UNIT_DAY;
		} else if (*number < MULTI_MONTH) {
			multiplier = MULTI_WEEK;
			new_unit = UNIT_WEEK;
		} else if (*number < MULTI_YEAR) {
			multiplier = MULTI_MONTH;
			new_unit = UNIT_MONTH;
		} else {
			multiplier = MULTI_YEAR;
			new_unit = UNIT_YEAR;
		}
	}

	// Check for unit application without any remainder.
	if ((*number % multiplier) == 0) {
		*number /= multiplier;
		*unit = new_unit;
	} else {
		*unit = basic_unit;
	}
}

_public_
int yp_int_to_txt(
	YP_BIN_TXT_PARAMS,
	yp_style_t style)
{
	YP_CHECK_PARAMS_TXT;

	char unit[2] = { '\0' };
	int64_t number = wire_ctx_read_u64(in);
	add_unit(&number, unit, style);

	int ret = snprintf((char *)out->position, wire_ctx_available(out),
	                   "%"PRId64"%s", number, unit);
	if (ret <= 0 || ret >= wire_ctx_available(out)) {
		return KNOT_ESPACE;
	}
	wire_ctx_skip(out, ret);

	YP_CHECK_RET;
}

static uint8_t sock_type_guess(
	const uint8_t *str,
	size_t len,
	const uint8_t **if_name)
{
	size_t dots = 0;
	size_t semicolons = 0;
	size_t digits = 0;

	// Analyze the string.
	for (size_t i = 0; i < len; i++) {
		if (str[i] == '.') dots++;
		else if (str[i] == ':') semicolons++;
		else if (is_digit(str[i])) digits++;
	}

	// Guess socket type.
	if (semicolons >= 1) {
		*if_name = (const uint8_t *)strchr((const char *)str, '%');
		if (*if_name == NULL) {
			return ADDR_TYPE_IPV6;
		} else {
			return ADDR_TYPE_IPV6_LINKLOCAL;
		}
	} else if (semicolons == 0 && dots == 3 && digits >= 3) {
		return ADDR_TYPE_IPV4;
	} else {
		return ADDR_TYPE_UNIX;
	}
}

_public_
int yp_addr_noport_to_bin(
	YP_TXT_BIN_PARAMS,
	bool allow_unix)
{
	YP_CHECK_PARAMS_BIN;

	struct in_addr  addr4;
	struct in6_addr addr6;

	const uint8_t *if_name = NULL;
	uint8_t type = sock_type_guess(in->position, YP_LEN, &if_name);

	// Copy address to the buffer to limit inet_pton overread.
	char buf[INET6_ADDRSTRLEN];
	if (is_ip_addr(type)) {
		size_t len = YP_LEN;
		if (if_name != NULL) {
			if (if_name + 1 >= stop) { // Missing inteface name.
				return KNOT_EINVAL;
			}
			len = if_name - in->position;
		}

		wire_ctx_t buf_ctx = copy_in(in, len, buf, sizeof(buf));
		if (buf_ctx.error != KNOT_EOK) {
			return buf_ctx.error;
		}
	}

	// Write address type.
	wire_ctx_write_u8(out, type);

	// Write address as such.
	if (is_addr_ipv4(type) && inet_pton(AF_INET, buf, &addr4) == 1) {
		wire_ctx_write(out, (uint8_t *)&(addr4.s_addr),
		               sizeof(addr4.s_addr));
	} else if ((is_addr_ipv6(type) || is_addr_ipv6_linklocal(type)) &&
	           inet_pton(AF_INET6, buf, &addr6) == 1) {
		wire_ctx_write(out, (uint8_t *)&(addr6.s6_addr),
		               sizeof(addr6.s6_addr));
		if (if_name != NULL) {
			assert(is_addr_ipv6_linklocal(type));
			wire_ctx_skip(in, sizeof(uint8_t));
			yp_str_to_bin(in, out, stop);
		}
	} else if (is_addr_unix(type) && allow_unix) {
		int ret = yp_str_to_bin(in, out, stop);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		return KNOT_EINVAL;
	}

	YP_CHECK_RET;
}

_public_
int yp_addr_noport_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	struct in_addr  addr4;
	struct in6_addr addr6;

	int ret;

	uint8_t type = wire_ctx_read_u8(in);
	switch (type) {
	case ADDR_TYPE_UNIX:
		ret = yp_str_to_txt(in, out);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	case ADDR_TYPE_IPV4:
		wire_ctx_read(in, &(addr4.s_addr), sizeof(addr4.s_addr));
		if (knot_inet_ntop(AF_INET, &addr4, (char *)out->position,
		    wire_ctx_available(out)) == NULL) {
			return KNOT_EINVAL;
		}
		wire_ctx_skip(out, strlen((char *)out->position));
		break;
	case ADDR_TYPE_IPV6:
	case ADDR_TYPE_IPV6_LINKLOCAL:
		wire_ctx_read(in, &(addr6.s6_addr), sizeof(addr6.s6_addr));
		if (knot_inet_ntop(AF_INET6, &addr6, (char *)out->position,
		    wire_ctx_available(out)) == NULL) {
			return KNOT_EINVAL;
		}
		wire_ctx_skip(out, strlen((char *)out->position));

		if (is_addr_ipv6_linklocal(type) && *in->position != '\0') {
			wire_ctx_write_u8(out, '%');
			ret = yp_str_to_txt(in, out);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		break;
	default:
		return KNOT_EINVAL;
	}

	YP_CHECK_RET;
}

_public_
int yp_addr_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Check for address@port separator.
	const uint8_t *pos = (uint8_t *)strrchr((char *)in->position, '@');
	// Ignore out-of-bounds result.
	if (pos >= stop) {
		pos = NULL;
	}

	// Store address type position.
	uint8_t *type = out->position;

	// Write the address without a port.
	int ret = yp_addr_noport_to_bin(in, out, pos, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (pos != NULL) {
		if (is_addr_unix(*type)) {
			// Rewrite string terminator.
			wire_ctx_skip(out, -1);
			// Append the rest (separator and port) as a string.
			ret = yp_str_to_bin(in, out, stop);
		} else {
			// Skip the separator.
			wire_ctx_skip(in, sizeof(uint8_t));

			// Write the port as a number.
			ret = yp_int_to_bin(in, out, stop, 0, UINT16_MAX, YP_SNONE);
		}
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else if (is_ip_addr(*type)) {
		wire_ctx_write_u64(out, (uint64_t)-1);
	}

	YP_CHECK_RET;
}

_public_
int yp_addr_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Store address type position.
	uint8_t *type = in->position;

	// Write address.
	int ret = yp_addr_noport_to_txt(in, out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Write port.
	if (is_ip_addr(*type)) {
		int64_t port = wire_ctx_read_u64(in);

		if (port >= 0) {
			// Write separator.
			wire_ctx_write_u8(out, '@');

			// Write port.
			wire_ctx_skip(in, -sizeof(uint64_t));
			ret = yp_int_to_txt(in, out, YP_SNONE);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	YP_CHECK_RET;
}

_public_
int yp_addr_range_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Format: 0 - single address, 1 - address prefix, 2 - address range.
	uint8_t format = 0;

	const bool unix_path = (in->position[0] == '/');
	const uint8_t *pos = NULL;

	if (!unix_path) {
		// Check for the "addr/mask" format.
		pos = (uint8_t *)strchr((char *)in->position, '/');
		if (pos >= stop) {
			pos = NULL;
		}

		if (pos != NULL) {
			format = 1;
		} else {
			// Check for the "addr1-addr2" format.
			pos = (uint8_t *)strchr((char *)in->position, '-');
			if (pos >= stop) {
				pos = NULL;
			}
			if (pos != NULL) {
				format = 2;
			}
		}
	}

	// Store address1 type position.
	uint8_t *type1 = out->position;

	// Write the first address.
	int ret = yp_addr_noport_to_bin(in, out, pos, unix_path);
	if (ret != KNOT_EOK) {
		return ret;
	}

	wire_ctx_write_u8(out, format);

	switch (format) {
	case 1:
		// Skip the separator.
		wire_ctx_skip(in, sizeof(uint8_t));

		// Write the prefix length.
		ret = yp_int_to_bin(in, out, stop, 0, (*type1 == 4) ? 32 : 128,
		                    YP_SNONE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	case 2:
		// Skip the separator.
		wire_ctx_skip(in, sizeof(uint8_t));

		// Store address2 type position.
		uint8_t *type2 = out->position;

		// Write the second address.
		ret = yp_addr_noport_to_bin(in, out, stop, false);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check for address mismatch.
		if (*type1 != *type2) {
			return KNOT_EINVAL;
		}
		break;
	default:
		break;
	}

	YP_CHECK_RET;
}

_public_
int yp_addr_range_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Write the first address.
	int ret = yp_addr_noport_to_txt(in, out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t format = wire_ctx_read_u8(in);

	switch (format) {
	case 1:
		// Write the separator.
		wire_ctx_write_u8(out, '/');

		// Write the prefix length.
		ret = yp_int_to_txt(in, out, YP_SNONE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	case 2:
		// Write the separator.
		wire_ctx_write_u8(out, '-');

		// Write the second address.
		ret = yp_addr_noport_to_txt(in, out);
		if (ret != KNOT_EOK) {
			return ret;
		}
		break;
	default:
		break;
	}

	YP_CHECK_RET;
}

_public_
int yp_option_to_bin(
	YP_TXT_BIN_PARAMS,
	const knot_lookup_t *opts)
{
	YP_CHECK_PARAMS_BIN;

	while (opts->name != NULL) {
		if (YP_LEN == strlen(opts->name) &&
		    strncasecmp((char *)in->position, opts->name, YP_LEN) == 0) {
			wire_ctx_write_u8(out, opts->id);
			wire_ctx_skip(in, YP_LEN);
			YP_CHECK_RET;
		}
		opts++;
	}

	return KNOT_EINVAL;
}

_public_
int yp_option_to_txt(
	YP_BIN_TXT_PARAMS,
	const knot_lookup_t *opts)
{
	uint8_t id = wire_ctx_read_u8(in);

	while (opts->name != NULL) {
		if (id == opts->id) {
			int ret = snprintf((char *)out->position,
			                   wire_ctx_available(out), "%s",
			                   opts->name);
			if (ret <= 0 || ret >= wire_ctx_available(out)) {
				return KNOT_ESPACE;
			}
			wire_ctx_skip(out, ret);
			YP_CHECK_RET;
		}
		opts++;
	}

	return KNOT_EINVAL;
}

_public_
int yp_dname_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Copy dname string to the buffer to limit dname_from_str overread.
	knot_dname_txt_storage_t buf;
	wire_ctx_t buf_ctx = copy_in(in, YP_LEN, buf, sizeof(buf));
	if (buf_ctx.error != KNOT_EOK) {
		return buf_ctx.error;
	}

	// Convert the dname.
	if (knot_dname_from_str(out->position, buf, wire_ctx_available(out)) == NULL) {
		return KNOT_EINVAL;
	}

	// Check the result and count the length.
	int ret = knot_dname_wire_check(out->position,
	                                out->position + wire_ctx_available(out),
	                                NULL);
	if (ret <= 0) {
		return KNOT_EINVAL;
	}

	// Convert the result to lower case.
	knot_dname_to_lower(out->position);

	wire_ctx_skip(out, ret);

	YP_CHECK_RET;
}

_public_
int yp_dname_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	if (knot_dname_to_str((char *)out->position, in->position,
	                      wire_ctx_available(out)) == NULL) {
		return KNOT_EINVAL;
	}

	wire_ctx_skip(out, strlen((char *)out->position));

	YP_CHECK_RET;
}

static int hex_to_num(char hex) {
	if (hex >= '0' && hex <= '9') return hex - '0';
	if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
	if (hex >= 'A' && hex <= 'F') return hex - 'A' + 10;
	return -1;
}

_public_
int yp_hex_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Check for hex notation (leading "0x").
	if (wire_ctx_available(in) >= 2 &&
	    in->position[0] == '0' && in->position[1] == 'x') {
		wire_ctx_skip(in, 2);

		if (YP_LEN % 2 != 0) {
			return KNOT_EINVAL;
		}

		// Write data length.
		wire_ctx_write_u16(out, YP_LEN / 2);

		// Decode hex string.
		while (YP_LEN > 0) {
			uint8_t buf[2] = { 0 };
			wire_ctx_read(in, buf, sizeof(buf));

			if (!is_xdigit(buf[0]) ||
			    !is_xdigit(buf[1])) {
				return KNOT_EINVAL;
			}

			wire_ctx_write_u8(out, 16 * hex_to_num(buf[0]) +
			                            hex_to_num(buf[1]));
		}
	} else {
		// Write data length.
		wire_ctx_write_u16(out, YP_LEN);

		// Write textual string (without terminator).
		wire_ctx_write(out, in->position, YP_LEN);
		wire_ctx_skip(in, YP_LEN);
	}

	YP_CHECK_RET;
}

_public_
int yp_hex_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	size_t len = wire_ctx_read_u16(in);

	bool printable = true;

	// Check for printable string.
	for (size_t i = 0; i < len; i++) {
		if (!is_print(in->position[i])) {
			printable = false;
			break;
		}
	}

	if (printable) {
		wire_ctx_write(out, in->position, len);
		wire_ctx_skip(in, len);
	} else {
		const char *prefix = "0x";
		const char *hex = "0123456789ABCDEF";

		// Write hex prefix.
		wire_ctx_write(out, (uint8_t *)prefix, strlen(prefix));

		// Encode data to hex.
		for (size_t i = 0; i < len; i++) {
			uint8_t bin = wire_ctx_read_u8(in);
			wire_ctx_write_u8(out, hex[bin / 16]);
			wire_ctx_write_u8(out, hex[bin % 16]);
		}
	}

	// Write the terminator.
	wire_ctx_write_u8(out, '\0');
	wire_ctx_skip(out, -1);

	YP_CHECK_RET;
}

_public_
int yp_base64_to_bin(
	YP_TXT_BIN_PARAMS)
{
	YP_CHECK_PARAMS_BIN;

	// Reserve some space for data length.
	wire_ctx_skip(out, sizeof(uint16_t));

	int ret = knot_base64_decode(in->position, YP_LEN, out->position,
	                        wire_ctx_available(out));
	if (ret < 0) {
		return ret;
	}
	wire_ctx_skip(in, YP_LEN);

	// Write the data length.
	wire_ctx_skip(out, -sizeof(uint16_t));
	wire_ctx_write_u16(out, ret);
	wire_ctx_skip(out, ret);

	YP_CHECK_RET;
}

_public_
int yp_base64_to_txt(
	YP_BIN_TXT_PARAMS)
{
	YP_CHECK_PARAMS_TXT;

	// Read the data length.
	uint16_t len = wire_ctx_read_u16(in);

	int ret = knot_base64_encode(in->position, len, out->position,
	                        wire_ctx_available(out));
	if (ret < 0) {
		return ret;
	}
	wire_ctx_skip(out, ret);

	// Write the terminator.
	wire_ctx_write_u8(out, '\0');
	wire_ctx_skip(out, -1);

	YP_CHECK_RET;
}

_public_
int yp_item_to_bin(
	const yp_item_t *item,
	const char *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len)
{
	if (item == NULL || txt == NULL || bin == NULL || bin_len == NULL) {
		return KNOT_EINVAL;
	}

	wire_ctx_t in = wire_ctx_init_const((const uint8_t *)txt, txt_len);
	wire_ctx_t out = wire_ctx_init(bin, *bin_len);

	int ret;
	size_t ref_len;

	switch (item->type) {
	case YP_TINT:
		ret = yp_int_to_bin(&in, &out, NULL, item->var.i.min,
		                    item->var.i.max, item->var.i.unit);
		break;
	case YP_TBOOL:
		ret = yp_bool_to_bin(&in, &out, NULL);
		break;
	case YP_TOPT:
		ret = yp_option_to_bin(&in, &out, NULL, item->var.o.opts);
		break;
	case YP_TSTR:
		ret = yp_str_to_bin(&in, &out, NULL);
		break;
	case YP_TADDR:
		ret = yp_addr_to_bin(&in, &out, NULL);
		break;
	case YP_TNET:
		ret = yp_addr_range_to_bin(&in, &out, NULL);
		break;
	case YP_TDNAME:
		ret = yp_dname_to_bin(&in, &out, NULL);
		break;
	case YP_THEX:
		ret = yp_hex_to_bin(&in, &out, NULL);
		break;
	case YP_TB64:
		ret = yp_base64_to_bin(&in, &out, NULL);
		break;
	case YP_TDATA:
		ret = item->var.d.to_bin(&in, &out, NULL);
		break;
	case YP_TREF:
		ref_len = wire_ctx_available(&out);
		ret = yp_item_to_bin(item->var.r.ref->var.g.id,
		                     (char *)in.position, wire_ctx_available(&in),
		                     out.position, &ref_len);
		wire_ctx_skip(&out, ref_len);
		break;
	default:
		ret = KNOT_EOK;
	}

	if (ret != KNOT_EOK) {
		return ret;
	} else if (in.error != KNOT_EOK) {
		return in.error;
	} else if (out.error != KNOT_EOK) {
		return out.error;
	}

	*bin_len = wire_ctx_offset(&out);

	return KNOT_EOK;
}

_public_
int yp_item_to_txt(
	const yp_item_t *item,
	const uint8_t *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len,
	yp_style_t style)
{
	if (item == NULL || bin == NULL || txt == NULL || txt_len == NULL) {
		return KNOT_EINVAL;
	}

	wire_ctx_t in = wire_ctx_init_const(bin, bin_len);
	wire_ctx_t out = wire_ctx_init((uint8_t *)txt, *txt_len);

	// Write leading quote.
	if (!(style & YP_SNOQUOTE)) {
		wire_ctx_write_u8(&out, '"');
	}

	int ret;
	size_t ref_len;

	switch (item->type) {
	case YP_TINT:
		ret = yp_int_to_txt(&in, &out, item->var.i.unit & style);
		break;
	case YP_TBOOL:
		ret = yp_bool_to_txt(&in, &out);
		break;
	case YP_TOPT:
		ret = yp_option_to_txt(&in, &out, item->var.o.opts);
		break;
	case YP_TSTR:
		ret = yp_str_to_txt(&in, &out);
		break;
	case YP_TADDR:
		ret = yp_addr_to_txt(&in, &out);
		break;
	case YP_TNET:
		ret = yp_addr_range_to_txt(&in, &out);
		break;
	case YP_TDNAME:
		ret = yp_dname_to_txt(&in, &out);
		break;
	case YP_THEX:
		ret = yp_hex_to_txt(&in, &out);
		break;
	case YP_TB64:
		ret = yp_base64_to_txt(&in, &out);
		break;
	case YP_TDATA:
		ret = item->var.d.to_txt(&in, &out);
		break;
	case YP_TREF:
		ref_len = wire_ctx_available(&out);
		ret = yp_item_to_txt(item->var.r.ref->var.g.id,
		                     in.position, wire_ctx_available(&in),
		                     (char *)out.position,
		                     &ref_len, style | YP_SNOQUOTE);
		wire_ctx_skip(&out, ref_len);
		break;
	default:
		ret = KNOT_EOK;
	}

	// Write trailing quote.
	if (!(style & YP_SNOQUOTE)) {
		wire_ctx_write_u8(&out, '"');
	}

	// Write string terminator.
	wire_ctx_write_u8(&out, '\0');
	wire_ctx_skip(&out, -1);

	if (ret != KNOT_EOK) {
		return ret;
	} else if (in.error != KNOT_EOK) {
		return in.error;
	} else if (out.error != KNOT_EOK) {
		return out.error;
	}

	*txt_len = wire_ctx_offset(&out);

	return KNOT_EOK;
}

_public_
struct sockaddr_storage yp_addr_noport(
	const uint8_t *data)
{
	struct sockaddr_storage ss = { AF_UNSPEC };

	// Read address type.
	uint8_t type = *data;
	data += sizeof(type);

	size_t addr_len;

	// Set address.
	switch (type) {
	case ADDR_TYPE_UNIX:
		sockaddr_set(&ss, AF_UNIX, (char *)data, 0);
		break;
	case ADDR_TYPE_IPV4:
		addr_len = sizeof(((struct in_addr *)NULL)->s_addr);
		sockaddr_set_raw(&ss, AF_INET, data, addr_len);
		break;
	case ADDR_TYPE_IPV6:
	case ADDR_TYPE_IPV6_LINKLOCAL:
		addr_len = sizeof(((struct in6_addr *)NULL)->s6_addr);
		sockaddr_set_raw(&ss, AF_INET6, data, addr_len);
		if (is_addr_ipv6_linklocal(type)) {
			struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&ss;
			sa->sin6_scope_id = if_nametoindex((const char *)data + addr_len);
			// Ignore if such an interface doesn't exist.
		}
		break;
	}

	return ss;
}

_public_
struct sockaddr_storage yp_addr(
	const uint8_t *data,
	bool *no_port)
{
	uint8_t type = *data;
	struct sockaddr_storage ss = yp_addr_noport(data);

	size_t addr_len;

	// Get binary address length.
	switch (type) {
	case ADDR_TYPE_IPV4:
		addr_len = sizeof(((struct in_addr *)NULL)->s_addr);
		break;
	case ADDR_TYPE_IPV6:
	case ADDR_TYPE_IPV6_LINKLOCAL:
		addr_len = sizeof(((struct in6_addr *)NULL)->s6_addr);
		break;
	default:
		addr_len = 0;
		*no_port = true;
	}

	if (addr_len > 0) {
		const uint8_t *port_pos = data + sizeof(uint8_t) + addr_len;
		if (is_addr_ipv6_linklocal(type)) {
			port_pos += strlen((char *)port_pos) + 1;
		}
		int64_t port = knot_wire_read_u64(port_pos);
		if (port >= 0) {
			sockaddr_port_set(&ss, port);
			*no_port = false;
		} else {
			*no_port = true;
		}
	}

	return ss;
}
