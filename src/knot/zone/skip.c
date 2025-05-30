/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/zone/skip.h"
#include "knot/zone/zonefile.h"

knot_dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_NORMAL)

// NOTE check against knot_rrtype_is_dnssec()
static const uint16_t dnssec_types[] = {
	KNOT_RRTYPE_DNSKEY,
	KNOT_RRTYPE_RRSIG,
	KNOT_RRTYPE_NSEC,
	KNOT_RRTYPE_NSEC3,
	KNOT_RRTYPE_NSEC3PARAM,
	KNOT_RRTYPE_CDNSKEY,
	KNOT_RRTYPE_CDS,
	0
};

static const uint16_t dnssec_diff_types[] = {
	KNOT_RRTYPE_RRSIG,
	KNOT_RRTYPE_NSEC,
	KNOT_RRTYPE_NSEC3,
	KNOT_RRTYPE_NSEC3PARAM,
	0
};

static int skip_add(zone_skip_t *skip, uint16_t type)
{
	return rrtype_dynarray_add(skip, &type) == NULL ? KNOT_ENOMEM : KNOT_EOK;
}

static int skip_add_dnssec(zone_skip_t *skip, const uint16_t types[])
{
	int ret = KNOT_EOK;
	for (const uint16_t *t = types; *t != 0 && ret == KNOT_EOK; t++) {
		ret = skip_add(skip, *t);
	}
	return ret;
}

static int skip_add_string(zone_skip_t *skip, const char *type_str)
{
	if (strncasecmp(type_str, "dnssec", 7) == 0) {
		return skip_add_dnssec(skip, dnssec_types);
	} else {
		uint16_t type = 0;
		if (knot_rrtype_from_string(type_str, &type) > -1) {
			return skip_add(skip, type);
		} else {
			return KNOT_EINVAL;
		}
	}
}

static void skip_add_finish(zone_skip_t *skip)
{
	rrtype_dynarray_sort_dedup(skip);
}

int zone_skip_add(zone_skip_t *skip, const char *type_str)
{
	int ret = skip_add_string(skip, type_str);
	skip_add_finish(skip);
	return ret;
}

int zone_skip_add_dnssec_diff(zone_skip_t *skip)
{
	int ret = skip_add_dnssec(skip, dnssec_diff_types);
	skip_add_finish(skip);
	return ret;
}

int zone_skip_from_conf(zone_skip_t *skip, conf_val_t *val)
{
	int ret = KNOT_EOK;

	while (val->code == KNOT_EOK && ret == KNOT_EOK) {
		ret = skip_add_string(skip, conf_str(val));
		conf_val_next(val);
	}

	if (val->code == KNOT_EOF) {
		conf_val_reset(val);
	}
	skip_add_finish(skip);

	if (ret != KNOT_EOK) {
		zone_skip_free(skip);
	}

	return ret;
}

int zonefile_write_skip(const char *path, struct zone_contents *zone, conf_t *conf)
{
	conf_val_t skip_val = conf_zone_get(conf, C_ZONEFILE_SKIP, zone->apex->owner);
	zone_skip_t skip = { 0 };
	int ret = zone_skip_from_conf(&skip, &skip_val);
	if (ret == KNOT_EOK) {
		ret = zonefile_write(path, zone, &skip);
	}
	zone_skip_free(&skip);
	return ret;
}
