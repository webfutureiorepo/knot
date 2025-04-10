/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libdnssec/random.h"
#include "utils/knsupdate/knsupdate_exec.h"
#include "utils/knsupdate/knsupdate_interactive.h"
#include "utils/common/exec.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "utils/common/sign.h"
#include "utils/common/token.h"
#include "libknot/libknot.h"
#include "contrib/ctype.h"
#include "contrib/getline.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "contrib/openbsd/strlcpy.h"

/* Declarations of cmd parse functions. */
typedef int (*cmd_handle_f)(const char *lp, knsupdate_params_t *params);
int cmd_add(const char* lp, knsupdate_params_t *params);
int cmd_answer(const char* lp, knsupdate_params_t *params);
int cmd_class(const char* lp, knsupdate_params_t *params);
int cmd_debug(const char* lp, knsupdate_params_t *params);
int cmd_del(const char* lp, knsupdate_params_t *params);
int cmd_gsstsig(const char* lp, knsupdate_params_t *params);
int cmd_key(const char* lp, knsupdate_params_t *params);
int cmd_local(const char* lp, knsupdate_params_t *params);
int cmd_nxdomain(const char *lp, knsupdate_params_t *params);
int cmd_nxrrset(const char *lp, knsupdate_params_t *params);
int cmd_oldgsstsig(const char* lp, knsupdate_params_t *params);
int cmd_origin(const char* lp, knsupdate_params_t *params);
int cmd_prereq(const char* lp, knsupdate_params_t *params);
int cmd_exit(const char* lp, knsupdate_params_t *params);
int cmd_realm(const char* lp, knsupdate_params_t *params);
int cmd_send(const char* lp, knsupdate_params_t *params);
int cmd_server(const char* lp, knsupdate_params_t *params);
int cmd_show(const char* lp, knsupdate_params_t *params);
int cmd_ttl(const char* lp, knsupdate_params_t *params);
int cmd_update(const char* lp, knsupdate_params_t *params);
int cmd_yxdomain(const char *lp, knsupdate_params_t *params);
int cmd_yxrrset(const char *lp, knsupdate_params_t *params);
int cmd_zone(const char* lp, knsupdate_params_t *params);

/* Sorted list of commands.
 * This way we could identify command byte-per-byte and
 * cancel early if the next is lexicographically greater.
 */
const char* knsupdate_cmd_array[] = {
	"\x3" "add",
	"\x6" "answer",
	"\x5" "class",         /* {classname} */
	"\x5" "debug",
	"\x3" "del",
	"\x6" "delete",
	"\x4" "exit",
	"\x7" "gsstsig",
	"\x3" "key",           /* {[alg:]name} {secret} */
	"\x5" "local",         /* {address} [port] */
	"\x8" "nxdomain",
	"\x7" "nxrrset",
	"\xa" "oldgsstsig",
	"\x6" "origin",        /* {name} */
	"\x6" "prereq",        /* (nx|yx)(domain|rrset) {domain-name} ... */
	"\x4" "quit",
	"\x5" "realm",         /* {[realm_name]} */
	"\x4" "send",
	"\x6" "server",        /* {servername} [port] */
	"\x4" "show",
	"\x3" "ttl",           /* {seconds} */
	"\x6" "update",        /* (add|delete) {domain-name} ... */
	"\x8" "yxdomain",
	"\x7" "yxrrset",
	"\x4" "zone",          /* {zonename} */
	NULL
};

cmd_handle_f cmd_handle[] = {
	cmd_add,
	cmd_answer,
	cmd_class,
	cmd_debug,
	cmd_del,
	cmd_del,         /* delete/del synonyms */
	cmd_exit,
	cmd_gsstsig,
	cmd_key,
	cmd_local,
	cmd_nxdomain,
	cmd_nxrrset,
	cmd_oldgsstsig,
	cmd_origin,
	cmd_prereq,
	cmd_exit,        /* exit/quit synonyms */
	cmd_realm,
	cmd_send,
	cmd_server,
	cmd_show,
	cmd_ttl,
	cmd_update,
	cmd_yxdomain,
	cmd_yxrrset,
	cmd_zone,
};

/* {prereq} command table. */
const char* pq_array[] = {
	"\x8" "nxdomain",
	"\x7" "nxrrset",
	"\x8" "yxdomain",
	"\x7" "yxrrset",
	NULL
};

enum {
	PQ_NXDOMAIN = 0,
	PQ_NXRRSET,
	PQ_YXDOMAIN,
	PQ_YXRRSET
};

/* RR parser flags */
enum {
	PARSE_NODEFAULT = 1 << 0, /* Do not fill defaults. */
	PARSE_NAMEONLY  = 1 << 1, /* Parse only name. */
	PARSE_NOTTL     = 1 << 2  /* Ignore TTL item. */
};

static bool dname_isvalid(const char *lp)
{
	knot_dname_t *dn = knot_dname_from_str_alloc(lp);
	if (dn == NULL) {
		return false;
	}
	knot_dname_free(dn, NULL);
	return true;
}

/* This is probably redundant, but should be a bit faster so let's keep it. */
static int parse_full_rr(zs_scanner_t *s, const char* lp)
{
	if (zs_set_input_string(s, lp, strlen(lp)) != 0 ||
	    zs_parse_all(s) != 0) {
		ERR("invalid record (%s)", zs_strerror(s->error.code));
		return KNOT_EPARSEFAIL;
	}

	/* Class must not differ from specified. */
	if (s->r_class != s->default_class) {
		char cls_s[16] = "";
		knot_rrclass_to_string(s->default_class, cls_s, sizeof(cls_s));
		ERR("class mismatch '%s'", cls_s);
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

static int parse_partial_rr(zs_scanner_t *s, const char *lp, unsigned flags)
{
	knot_dname_txt_storage_t owner_str = { 0 };

	/* Extract owner. */
	size_t len = strcspn(lp, SEP_CHARS);
	memcpy(owner_str, lp, len);

	/* Check if ORIGIN (@) or FQDN. */
	bool origin = false;
	bool fqdn = true;
	if (len == 1 && owner_str[0] == '@') {
		origin = true;
		fqdn = false;
	} else if (owner_str[len - 1] != '.') {
		fqdn = false;
	}

	/* Convert textual owner to dname. */
	if (!origin) {
		knot_dname_storage_t owner;
		if (knot_dname_from_str(owner, owner_str, sizeof(owner)) == NULL) {
			return KNOT_EINVAL;
		}

		s->r_owner_length = knot_dname_size(owner);
		memcpy(s->r_owner, owner, s->r_owner_length);
	} else {
		s->r_owner_length = 0;
	}

	/* Append origin if not FQDN. */
	if (!fqdn) {
		if (!origin) {
			s->r_owner_length--;
		}
		memcpy(s->r_owner + s->r_owner_length, s->zone_origin,
		       s->zone_origin_length);
		s->r_owner_length += s->zone_origin_length;
	}

	lp = tok_skipspace(lp + len);

	/* Initialize */
	s->r_type = KNOT_RRTYPE_ANY;
	s->r_class = s->default_class;
	s->r_data_length = 0;
	if (flags & PARSE_NODEFAULT) {
		s->r_ttl = 0;
	} else {
		s->r_ttl = s->default_ttl;
	}

	/* Parse only name? */
	if (flags & PARSE_NAMEONLY) {
		if (*lp != '\0') {
			WARN("ignoring input data '%s'", lp);
		}
		return KNOT_EOK;
	}

	/* Now there could be [ttl] [class] [type [data...]]. */
	char *np = NULL;
	long ttl = strtol(lp, &np, 10);
	if (ttl >= 0 && np && (*np == '\0' || is_space(*np))) {
		DBG("%s: parsed ttl=%lu", __func__, ttl);
		if (flags & PARSE_NOTTL) {
			WARN("ignoring TTL value '%ld'", ttl);
		} else {
			s->r_ttl = ttl;
		}
		lp = tok_skipspace(np);
	}

	uint16_t num;
	char *buff = NULL;
	char *cls = NULL;
	char *type = NULL;

	/* Try to find class. */
	len = strcspn(lp, SEP_CHARS);
	if (len > 0) {
		buff = strndup(lp, len);
	}

	if (knot_rrclass_from_string(buff, &num) == 0) {
		/* Class must not differ from specified. */
		if (num != s->default_class) {
			ERR("class mismatch '%s'", buff);
			free(buff);
			return KNOT_EPARSEFAIL;
		}
		cls = buff;
		buff = NULL;
		s->r_class = num;
		DBG("%s: parsed class=%u '%s'", __func__, s->r_class, cls);
		lp = tok_skipspace(lp + len);
	}

	/* Try to parser type. */
	if (cls != NULL) {
		len = strcspn(lp, SEP_CHARS);
		if (len > 0) {
			buff = strndup(lp, len);
		}
	}
	if (knot_rrtype_from_string(buff, &num) == 0) {
		type = buff;
		buff = NULL;
		s->r_type = num;
		DBG("%s: parsed type=%u '%s'", __func__, s->r_type, type);
		lp = tok_skipspace(lp + len);
	}

	free(buff);

	/* Remainder */
	if (*lp == '\0') {
		free(cls);
		free(type);
		return KNOT_EOK;
	}

	/* Need to parse rdata, synthetize input. */
	char *rr = sprintf_alloc(" %u IN %s %s\n", s->r_ttl, type, lp);
	free(cls);
	free(type);
	if (rr == NULL) {
		return KNOT_ENOMEM;
	}
	if (zs_set_input_string(s, rr, strlen(rr)) != 0 ||
	    zs_parse_all(s) != 0) {
		ERR("invalid rdata (%s)", zs_strerror(s->error.code));
		free(rr);
		return KNOT_EPARSEFAIL;
	}
	free(rr);

	return KNOT_EOK;
}

static srv_info_t *parse_host(const char *lp, const char* default_port)
{
	/* Extract server address. */
	srv_info_t *srv = NULL;
	size_t len = strcspn(lp, SEP_CHARS);
	char *addr = strndup(lp, len);
	if (!addr) return NULL;
	DBG("%s: parsed addr: %s", __func__, addr);

	/* Store port/service if present. */
	lp = tok_skipspace(lp + len);
	if (*lp == '\0') {
		srv = srv_info_create(addr, default_port);
		free(addr);
		return srv;
	}

	len = strcspn(lp, SEP_CHARS);
	char *port = strndup(lp, len);
	if (!port) {
		free(addr);
		return NULL;
	}
	DBG("%s: parsed port: %s", __func__, port);

	/* Create server struct. */
	srv = srv_info_create(addr, port);
	free(addr);
	free(port);
	return srv;
}

/* Append parsed RRSet to list. */
static int rr_list_append(zs_scanner_t *s, list_t *target_list, knot_mm_t *mm)
{
	knot_rrset_t *rr = knot_rrset_new(s->r_owner, s->r_type, s->r_class,
	                                  s->r_ttl, NULL);
	if (!rr) {
		DBG("%s: failed to create rrset", __func__);
		return KNOT_ENOMEM;
	}

	/* Create RDATA. */
	int ret = knot_rrset_add_rdata(rr, s->r_data, s->r_data_length, NULL);
	if (ret != KNOT_EOK) {
		DBG("%s: failed to set rrset from wire (%s)",
		    __func__, knot_strerror(ret));
		knot_rrset_free(rr, NULL);
		return ret;
	}

	if (ptrlist_add(target_list, rr, mm) == NULL) {
		knot_rrset_free(rr, NULL);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Write RRSet list to packet section. */
static int rr_list_to_packet(knot_pkt_t *dst, list_t *list)
{
	assert(dst != NULL);
	assert(list != NULL);

	ptrnode_t *node;
	WALK_LIST(node, *list) {
		int ret = knot_pkt_put(dst, KNOT_COMPR_HINT_NONE,
		                       (knot_rrset_t *)node->d, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*! \brief Build UPDATE query. */
static int build_query(knsupdate_params_t *params)
{
	/* Clear old query. */
	knot_pkt_t *query = params->query;
	knot_pkt_clear(query);

	/* Write question. */
	knot_wire_set_id(query->wire, dnssec_random_uint16_t());
	knot_wire_set_opcode(query->wire, KNOT_OPCODE_UPDATE);
	knot_dname_t *qname = knot_dname_from_str_alloc(params->zone);
	int ret = knot_pkt_put_question(query, qname, params->class_num,
	                                KNOT_RRTYPE_SOA);
	knot_dname_free(qname, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Now, PREREQ => ANSWER section. */
	ret = knot_pkt_begin(query, KNOT_ANSWER);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Write PREREQ. */
	ret = rr_list_to_packet(query, &params->prereq_list);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Now, UPDATE data => AUTHORITY section. */
	ret = knot_pkt_begin(query, KNOT_AUTHORITY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Write UPDATE data. */
	return rr_list_to_packet(query, &params->update_list);
}

static int pkt_sendrecv(knsupdate_params_t *params)
{
	net_t net;
	int   ret;

	ret = net_init(params->srcif,
	               params->server,
	               get_iptype(params->ip, params->server),
	               get_socktype(params->protocol, KNOT_RRTYPE_SOA),
	               params->wait,
	               NET_FLAGS_NONE,
	               NULL,
	               NULL,
	               &net);
	if (ret != KNOT_EOK) {
		return -1;
	}

	ret = net_init_crypto(&net, &params->tls_params, NULL, &params->quic_params);
	if (ret != 0) {
		ERR("failed to initialize crypto context (%s)", knot_strerror(ret));
		net_clean(&net);
		return -1;
	}

	ret = net_connect(&net);
	if (ret != KNOT_EOK) {
		ERR("failed to connect (%s)", knot_strerror(ret));
		net_clean(&net);
		return -1;
	}

	ret = net_send(&net, params->query->wire, params->query->size);
	if (ret != KNOT_EOK) {
		ERR("failed to send update (%s)", knot_strerror(ret));
		net_close(&net);
		net_clean(&net);
		return -1;
	}

	/* Clear response buffer. */
	knot_pkt_clear(params->answer);

	/* Wait for reception. */
	int rb = net_receive(&net, params->answer->wire, params->answer->max_size);
	if (rb <= 0) {
		ERR("failed to receive response (%s)", knot_strerror(rb));
		net_close(&net);
		net_clean(&net);
		return -1;
	} else {
		params->answer->size = rb;
	}

	net_close(&net);
	net_clean(&net);

	return rb;
}

int knsupdate_process_line(const char *line, knsupdate_params_t *params)
{
	/* Check for empty line or comment. */
	if (line[0] == '\0' || line[0] == ';') {
		return KNOT_EOK;
	}

	int ret = tok_find(line, knsupdate_cmd_array);
	if (ret < 0) {
		return ret; /* Syntax error - do nothing. */
	}

	const char *cmd = knsupdate_cmd_array[ret];
	const char *val = tok_skipspace(line + TOK_L(cmd));
	params->parser.error.counter = 0; /* Reset possible previous error. */
	ret = cmd_handle[ret](val, params);
	if (ret != KNOT_EOK) {
		DBG("operation '%s' failed (%s) on line '%s'",
		    TOK_S(cmd), knot_strerror(ret), line);
	}

	return ret;
}

static bool is_terminal(FILE *file)
{
	int fd = fileno(file);
	assert(fd >= 0);
	return isatty(fd);
}

static int process_lines(knsupdate_params_t *params, FILE *input)
{
	char *buf = NULL;
	size_t buflen = 0;
	if(is_terminal(input)) {
		return interactive_loop(params);
	}
	int ret = KNOT_EOK;

	/* Process lines. */
	while (!params->stop && knot_getline(&buf, &buflen, input) != -1) {
		/* Remove leading and trailing white space. */
		char *line = strstrip(buf);
		ret = knsupdate_process_line(line, params);
		memset(line, 0, strlen(line));
		free(line);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	if (buf != NULL) {
		memset(buf, 0, buflen);
		free(buf);
	}

	return ret;
}

int knsupdate_exec(knsupdate_params_t *params)
{
	if (!params) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* If no file specified, enter the interactive mode. */
	if (EMPTY_LIST(params->qfiles)) {
		return process_lines(params, stdin);
	}

	/* Read from each specified file. */
	ptrnode_t *n;
	WALK_LIST(n, params->qfiles) {
		const char *filename = (const char*)n->d;
		if (strcmp(filename, "-") == 0) {
			ret = process_lines(params, stdin);
			if (ret != KNOT_EOK) {
				break;
			}
			continue;
		}

		FILE *fp = fopen(filename, "r");
		if (!fp) {
			ERR("failed to open '%s' (%s)",
			    filename, strerror(errno));
			ret = KNOT_EFILE;
			break;
		}
		ret = process_lines(params, fp);
		fclose(fp);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int cmd_update(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* update is optional token, next add|del|delete */
	int bp = tok_find(lp, knsupdate_cmd_array);
	if (bp < 0) return bp; /* Syntax error. */

	/* allow only specific tokens */
	cmd_handle_f *h = cmd_handle;
	if (h[bp] != cmd_add && h[bp] != cmd_del) {
		ERR("unexpected token '%s' after 'update', allowed: '%s'",
		    lp, "{add|del|delete}");
		return KNOT_EPARSEFAIL;
	}

	return h[bp](tok_skipspace(lp + TOK_L(knsupdate_cmd_array[bp])), params);
}

int cmd_add(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	if (parse_full_rr(&params->parser, lp) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}

	return rr_list_append(&params->parser, &params->update_list, &params->mm);
}

int cmd_del(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	zs_scanner_t *rrp = &params->parser;
	int ret = parse_partial_rr(rrp, lp, PARSE_NODEFAULT);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check owner name. */
	if (rrp->r_owner_length == 0) {
		ERR("failed to parse owner name '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	rrp->r_ttl = 0; /* Set TTL = 0 when deleting. */

	/* When deleting whole RRSet, use ANY class */
	if (rrp->r_data_length == 0) {
		rrp->r_class = KNOT_CLASS_ANY;
	} else {
		rrp->r_class = KNOT_CLASS_NONE;
	}

	return rr_list_append(rrp, &params->update_list, &params->mm);
}

int cmd_class(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	uint16_t cls;

	if (knot_rrclass_from_string(lp, &cls) != 0) {
		ERR("failed to parse class '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	params->class_num = cls;
	params->parser.default_class = params->class_num;

	return KNOT_EOK;
}

int cmd_ttl(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	uint32_t ttl = 0;

	if (str_to_u32(lp, &ttl) != KNOT_EOK) {
		ERR("failed to parse ttl '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	return knsupdate_set_ttl(params, ttl);
}

int cmd_debug(const char* lp, _unused_ knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	msg_enable_debug(1);

	return KNOT_EOK;
}

int cmd_nxdomain(const char *lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	zs_scanner_t *s = &params->parser;
	int ret = parse_partial_rr(s, lp, PARSE_NODEFAULT | PARSE_NAMEONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	s->r_ttl = 0;
	s->r_class = KNOT_CLASS_NONE;

	return rr_list_append(s, &params->prereq_list, &params->mm);
}

int cmd_yxdomain(const char *lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	zs_scanner_t *s = &params->parser;
	int ret = parse_partial_rr(s, lp, PARSE_NODEFAULT | PARSE_NAMEONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	s->r_ttl = 0;
	s->r_class = KNOT_CLASS_ANY;

	return rr_list_append(s, &params->prereq_list, &params->mm);
}

int cmd_nxrrset(const char *lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	zs_scanner_t *s = &params->parser;
	int ret = parse_partial_rr(s, lp, PARSE_NOTTL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check owner name. */
	if (s->r_owner_length == 0) {
		ERR("failed to parse prereq owner name '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	s->r_ttl = 0;
	s->r_class = KNOT_CLASS_NONE;

	return rr_list_append(s, &params->prereq_list, &params->mm);
}

int cmd_yxrrset(const char *lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	zs_scanner_t *s = &params->parser;
	int ret = parse_partial_rr(s, lp, PARSE_NOTTL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check owner name. */
	if (s->r_owner_length == 0) {
		ERR("failed to parse prereq owner name '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	s->r_ttl = 0;
	if (s->r_data_length > 0) {
		s->r_class = KNOT_CLASS_IN;
	} else {
		s->r_class = KNOT_CLASS_ANY;
	}

	return rr_list_append(s, &params->prereq_list, &params->mm);
}

int cmd_prereq(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Scan prereq specifier ([ny]xrrset|[ny]xdomain) */
	int prereq_type = tok_find(lp, pq_array);
	if (prereq_type < 0) {
		return prereq_type;
	}

	const char *tok = pq_array[prereq_type];
	DBG("%s: type %s", __func__, TOK_S(tok));
	lp = tok_skipspace(lp + TOK_L(tok));
	if (strlen(lp) == 0) {
		ERR("missing prerequisite owner name");
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	switch(prereq_type) {
	case PQ_NXDOMAIN:
		ret = cmd_nxdomain(lp, params);
		break;
	case PQ_YXDOMAIN:
		ret = cmd_yxdomain(lp, params);
		break;
	case PQ_NXRRSET:
		ret = cmd_nxrrset(lp, params);
		break;
	case PQ_YXRRSET:
		ret = cmd_yxrrset(lp, params);
		break;
	default:
		ret = KNOT_ERROR;
	}

	return ret;
}

int cmd_exit(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	params->stop = true;

	return KNOT_EOK;
}

int cmd_send(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);
	DBG("sending packet");

	if (params->zone == NULL) {
		ERR("no zone specified");
		return KNOT_EINVAL;
	}

	/* Build query packet. */
	int ret = build_query(params);
	if (ret != KNOT_EOK) {
		ERR("failed to build UPDATE message (%s)", knot_strerror(ret));
		return ret;
	}

	/* Sign if key specified. */
	sign_context_t sign_ctx = { 0 };
	if (params->tsig_key.name) {
		ret = sign_context_init_tsig(&sign_ctx, &params->tsig_key);
		if (ret != KNOT_EOK) {
			ERR("failed to initialize signing context (%s)",
			    knot_strerror(ret));
			return ret;
		}

		ret = sign_packet(params->query, &sign_ctx);
		if (ret != KNOT_EOK) {
			ERR("failed to sign UPDATE message (%s)",
			    knot_strerror(ret));
			sign_context_deinit(&sign_ctx);
			return ret;
		}
	}

	int rb = 0;
	/* Send/recv message (1 try + N retries). */
	int tries = 1 + params->retries;
	for (; tries > 0; --tries) {
		rb = pkt_sendrecv(params);
		if (rb > 0) {
			break;
		}
	}

	/* Check Send/recv result. */
	if (rb <= 0) {
		sign_context_deinit(&sign_ctx);
		return KNOT_ECONNREFUSED;
	}

	/* Parse response. */
	ret = knot_pkt_parse(params->answer, KNOT_PF_NOCANON);
	if (ret != KNOT_EOK) {
		ERR("failed to parse response (%s)", knot_strerror(ret));
		sign_context_deinit(&sign_ctx);
		return ret;
	}

	/* Check signature if expected. */
	if (params->tsig_key.name) {
		ret = verify_packet(params->answer, &sign_ctx);
		sign_context_deinit(&sign_ctx);
		if (ret != KNOT_EOK) {
			print_packet(params->answer, NULL, 0, -1, 0, true,
			             &params->style);
			ERR("reply verification (%s)", knot_strerror(ret));
			return ret;
		}
	}

	/* Free RRSet lists. */
	knsupdate_reset(params);

	/* Check return code. */
	if (knot_pkt_ext_rcode(params->answer) != KNOT_RCODE_NOERROR) {
		print_packet(params->answer, NULL, 0, -1, 0, true, &params->style);
		ERR("update failed with error '%s'",
		    knot_pkt_ext_rcode_name(params->answer));
		ret = KNOT_ERROR;
	} else {
		DBG("update success");
	}

	return ret;
}

int cmd_zone(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Check zone name. */
	if (!dname_isvalid(lp)) {
		ERR("failed to parse zone '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	free(params->zone);
	params->zone = strdup(lp);

	return KNOT_EOK;
}

int cmd_server(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Parse host. */
	srv_info_t *srv = parse_host(lp, params->server->service);
	if (!srv) {
		ERR("failed to parse server '%s'", lp);
		return KNOT_ENOMEM;
	}

	srv_info_free(params->server);
	params->server = srv;

	return KNOT_EOK;
}

int cmd_local(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Parse host. */
	srv_info_t *srv = parse_host(lp, "0");
	if (!srv) {
		ERR("failed to parse local '%s'", lp);
		return KNOT_ENOMEM;
	}

	srv_info_free(params->srcif);
	params->srcif = srv;

	return KNOT_EOK;
}

int cmd_show(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	if (!params->query) {
		return KNOT_EOK;
	}

	printf("Update query:\n");
	build_query(params);
	print_packet(params->query, NULL, 0, -1, 0, false, &params->style);
	printf("\n");

	return KNOT_EOK;
}

int cmd_answer(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	if (!params->answer) {
		return KNOT_EOK;
	}

	printf("Answer:\n");
	print_packet(params->answer, NULL, 0, -1, 0, true, &params->style);

	return KNOT_EOK;
}

int cmd_key(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Convert to default format. */
	char *kstr = strdup(lp);
	if (!kstr) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EOK;

	/* Search for the name secret separation. Allow also alg:name:key form. */
	char *sep = strchr(kstr, ' ');
	if (sep != NULL) {
		/* Replace ' ' with ':'. More spaces are ignored in base64. */
		*sep = ':';
	}

	/* Override existing key. */
	knot_tsig_key_deinit(&params->tsig_key);

	ret = knot_tsig_key_init_str(&params->tsig_key, kstr);
	if (ret != KNOT_EOK) {
		ERR("invalid key specification");
	}

	free(kstr);

	return ret;
}

int cmd_origin(const char* lp, knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	/* Check zone name. */
	if (!dname_isvalid(lp)) {
		ERR("failed to parse zone '%s'", lp);
		return KNOT_EPARSEFAIL;
	}

	return knsupdate_set_origin(params, lp);
}

/*
 *   Not implemented.
 */

int cmd_gsstsig(const char* lp, _unused_ knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	ERR("gsstsig not supported");

	return KNOT_ENOTSUP;
}

int cmd_oldgsstsig(const char* lp, _unused_ knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	ERR("oldgsstsig not supported");

	return KNOT_ENOTSUP;
}

int cmd_realm(const char* lp, _unused_ knsupdate_params_t *params)
{
	DBG("%s: lp='%s'", __func__, lp);

	ERR("realm not supported");

	return KNOT_ENOTSUP;
}
