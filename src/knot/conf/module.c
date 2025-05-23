/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <glob.h>
#include <sys/stat.h>
#include <unistd.h>
#include <urcu.h>

#include "knot/conf/conf.h"
#include "knot/conf/confio.h"
#include "knot/conf/module.h"
#include "knot/common/log.h"
#include "knot/modules/static_modules.h"
#include "knot/nameserver/query_module.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/string.h"

#define LIB_EXTENSION ".so"

knot_dynarray_define(mod, module_t *, DYNARRAY_VISIBILITY_NORMAL)
knot_dynarray_define(old_schema, yp_item_t *, DYNARRAY_VISIBILITY_NORMAL)

static module_t STATIC_MODULES[] = {
	STATIC_MODULES_INIT
	{ NULL }
};

module_t *conf_mod_find(
	conf_t *conf,
	const char *name,
	size_t len,
	bool temporary)
{
	if (conf == NULL || name == NULL) {
		return NULL;
	}

	// First, search in static modules.
	for (module_t *mod = STATIC_MODULES; mod->api != NULL; mod++) {
		if (strncmp(name, mod->api->name, len) == 0) {
			return mod;
		}
	}

	module_type_t excluded_type = temporary ? MOD_EXPLICIT : MOD_TEMPORARY;

	// Second, search in dynamic modules.
	knot_dynarray_foreach(mod, module_t *, module, conf->modules) {
		if ((*module) != NULL && (*module)->type != excluded_type &&
		    strncmp(name, (*module)->api->name, len) == 0) {
			return (*module);
		}
	}

	return NULL;
}

static int mod_load(
	conf_t *conf,
	module_t *mod)
{
	static const yp_item_t module_common[] = {
		{ C_ID,      YP_TSTR,  YP_VNONE, CONF_IO_FREF },
		{ C_COMMENT, YP_TSTR,  YP_VNONE },
		{ NULL }
	};

	yp_item_t *sub_items = NULL;

	int ret;
	if (mod->api->config != NULL) {
		ret = yp_schema_merge(&sub_items, module_common, mod->api->config);
	} else {
		ret = yp_schema_copy(&sub_items, module_common);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Synthesise module config section name. */
	const size_t name_len = strlen(mod->api->name);
	if (name_len > YP_MAX_ITEM_NAME_LEN) {
		return KNOT_YP_EINVAL_ITEM;
	}
	char name[1 + YP_MAX_ITEM_NAME_LEN + 1];
	name[0] = name_len;
	memcpy(name + 1, mod->api->name, name_len + 1);

	const yp_item_t schema[] = {
		{ name, YP_TGRP, YP_VGRP = { sub_items },
		        YP_FALLOC | YP_FMULTI | CONF_IO_FRLD_MOD | CONF_IO_FRLD_ZONES,
		        { mod->api->config_check } },
		{ NULL }
	};

	yp_item_t *merged = NULL;
	ret = yp_schema_merge(&merged, conf->schema, schema);
	yp_schema_free(sub_items);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update configuration schema (with lazy free).
	yp_item_t **current_schema = &conf->schema;
	yp_item_t *old_schema = rcu_xchg_pointer(current_schema, merged);
	synchronize_rcu();
	old_schema_dynarray_add(&conf->old_schemas, &old_schema);

	return KNOT_EOK;
}

int conf_mod_load_common(
	conf_t *conf)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	// First, load static modules.
	for (module_t *mod = STATIC_MODULES; mod->api != NULL; mod++) {
		ret = mod_load(conf, mod);
		if (ret != KNOT_EOK) {
			log_error("module '%s', failed to load (%s)",
			          mod->api->name, knot_strerror(ret));
			break;
		}

		log_debug("module '%s', loaded static", mod->api->name);
	}

	// Second, try to load implicit shared modules if configured.
	if (strlen(MODULE_DIR) > 0) {
		struct stat path_stat;
		glob_t glob_buf = { 0 };

		char *path = sprintf_alloc("%s/*%s", MODULE_DIR, LIB_EXTENSION);
		if (path == NULL) {
			ret = KNOT_ENOMEM;
		} else if (stat(MODULE_DIR, &path_stat) != 0 ||
		           !S_ISDIR(path_stat.st_mode)) {
			if (errno == ENOENT) {
				// Module directory doesn't exist.
				ret = KNOT_EOK;
			} else {
				log_error("module, invalid directory '%s'",
				          MODULE_DIR);
				ret = KNOT_EINVAL;
			}
		} else if (access(MODULE_DIR, F_OK | R_OK) != 0) {
			log_error("module, failed to access directory '%s'",
			          MODULE_DIR);
			ret = KNOT_EACCES;
		} else {
			ret = glob(path, 0, NULL, &glob_buf);
			if (ret != 0 && ret != GLOB_NOMATCH) {
				log_error("module, failed to read directory '%s'",
				          MODULE_DIR);
				ret = KNOT_EACCES;
			} else {
				ret = KNOT_EOK;
			}
		}

		// Process each module in the directory.
		for (size_t i = 0; i < glob_buf.gl_pathc; i++) {
			(void)conf_mod_load_extra(conf, NULL, glob_buf.gl_pathv[i],
			                          MOD_IMPLICIT);
		}

		globfree(&glob_buf);
		free(path);
	}

	conf_mod_load_purge(conf, false);

	return ret;
}

int conf_mod_load_extra(
	conf_t *conf,
	const char *mod_name,
	const char *file_name,
	module_type_t type)
{
	if (conf == NULL || (mod_name == NULL && file_name == NULL)) {
		return KNOT_EINVAL;
	}

	// Synthesize module file name if not specified.
	char *tmp_name = NULL;
	if (file_name == NULL) {
		tmp_name = sprintf_alloc("%s/%s%s", MODULE_INSTDIR,
		                         mod_name + strlen(KNOTD_MOD_NAME_PREFIX),
		                         LIB_EXTENSION);
		if (tmp_name == NULL) {
			return KNOT_ENOMEM;
		}
		file_name = tmp_name;
	}

	void *handle = dlopen(file_name, RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		log_error("module, failed to open '%s' (%s)", file_name, dlerror());
		free(tmp_name);
		return KNOT_ENOENT;
	}
	(void)dlerror();

	knotd_mod_api_t *api = dlsym(handle, "knotd_mod_api");
	if (api == NULL) {
		char *err = dlerror();
		if (err == NULL) {
			err = "empty symbol";
		}
		log_error("module, invalid library '%s' (%s)", file_name, err);
		dlclose(handle);
		free(tmp_name);
		return KNOT_ENOENT;
	}
	free(tmp_name);

	if (api->version != KNOTD_MOD_ABI_VERSION) {
		log_error("module '%s', incompatible version", api->name);
		dlclose(handle);
		return KNOT_ENOTSUP;
	}

	if (api->name == NULL || (mod_name != NULL && strcmp(api->name, mod_name) != 0)) {
		log_error("module '%s', module name mismatch", api->name);
		dlclose(handle);
		return KNOT_ENOTSUP;
	}

	// Check if the module is already loaded.
	module_t *found = conf_mod_find(conf, api->name, strlen(api->name),
	                                type == MOD_TEMPORARY);
	if (found != NULL) {
		log_error("module '%s', duplicate module", api->name);
		dlclose(handle);
		return KNOT_EEXIST;
	}

	module_t *mod = calloc(1, sizeof(*mod));
	if (mod == NULL) {
		dlclose(handle);
		return KNOT_ENOMEM;
	}
	mod->api = api;
	mod->lib_handle = handle;
	mod->type = type;

	int ret = mod_load(conf, mod);
	if (ret != KNOT_EOK) {
		log_error("module '%s', failed to load (%s)", api->name,
		          knot_strerror(ret));
		dlclose(handle);
		free(mod);
		return ret;
	}

	mod_dynarray_add(&conf->modules, &mod);

	log_debug("module '%s', loaded shared", api->name);

	return KNOT_EOK;
}

static void unload_shared(
	module_t *mod)
{
	if (mod != NULL) {
		assert(mod->lib_handle);
		(void)dlclose(mod->lib_handle);
		free(mod);
	}
}

void conf_mod_load_purge(
	conf_t *conf,
	bool temporary)
{
	if (conf == NULL) {
		return;
	}

	// Switch the current temporary schema with the initial one.
	if (temporary && conf->old_schemas.size > 0) {
		yp_item_t **current_schema = &conf->schema;
		yp_item_t **initial = &(conf->old_schemas.arr(&conf->old_schemas))[0];

		yp_item_t *old_schema = rcu_xchg_pointer(current_schema, *initial);
		synchronize_rcu();
		*initial = old_schema;
	}

	knot_dynarray_foreach(old_schema, yp_item_t *, schema, conf->old_schemas) {
		yp_schema_free(*schema);
	}
	old_schema_dynarray_free(&conf->old_schemas);

	knot_dynarray_foreach(mod, module_t *, module, conf->modules) {
		if ((*module) != NULL && (*module)->type == MOD_TEMPORARY) {
			unload_shared((*module));
			*module = NULL; // Cannot remove from dynarray.
		}
	}
}

void conf_mod_unload_shared(
	conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	knot_dynarray_foreach(mod, module_t *, module, conf->modules) {
		unload_shared((*module));
	}
	mod_dynarray_free(&conf->modules);
}

#define LOG_ARGS(mod_id, msg) "module '%s%s%.*s', " msg, \
	mod_id->name + 1, (mod_id->len > 0) ? "/" : "", (int)mod_id->len, \
	mod_id->data

#define MOD_ID_LOG(zone, level, mod_id, msg, ...) \
	if (zone != NULL) \
		log_zone_##level(zone, LOG_ARGS(mod_id, msg), ##__VA_ARGS__); \
	else \
		log_##level(LOG_ARGS(mod_id, msg), ##__VA_ARGS__);

int conf_activate_modules(
	conf_t *conf,
	struct server *server,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	int ret = KNOT_EOK;

	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		ret = KNOT_EINVAL;
		goto activate_error;
	}

	conf_val_t val;

	// Get list of associated modules.
	if (zone_name != NULL) {
		val = conf_zone_get(conf, C_MODULE, zone_name);
	} else {
		val = conf_default_get(conf, C_GLOBAL_MODULE);
	}

	switch (val.code) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT: // Check if a module is configured at all.
	case KNOT_YP_EINVAL_ID:
		return KNOT_EOK;
	default:
		ret = val.code;
		goto activate_error;
	}

	// Create query plan.
	*query_plan = query_plan_create();
	if (*query_plan == NULL) {
		ret = KNOT_ENOMEM;
		goto activate_error;
	}

	// Initialize query modules list.
	init_list(query_modules);

	// Open the modules.
	while (val.code == KNOT_EOK) {
		conf_mod_id_t *mod_id = conf_mod_id(&val);
		if (mod_id == NULL) {
			ret = KNOT_ENOMEM;
			goto activate_error;
		}

		// Open the module.
		knotd_mod_t *mod = query_module_open(conf, server, mod_id, *query_plan,
		                                     zone_name);
		if (mod == NULL) {
			MOD_ID_LOG(zone_name, error, mod_id, "failed to open");
			conf_free_mod_id(mod_id);
			ret = KNOT_EMODINVAL;
			goto activate_error;
		}

		// Check the module scope.
		if ((zone_name == NULL && !(mod->api->flags & KNOTD_MOD_FLAG_SCOPE_GLOBAL)) ||
		    (zone_name != NULL && !(mod->api->flags & KNOTD_MOD_FLAG_SCOPE_ZONE))) {
			MOD_ID_LOG(zone_name, error, mod_id, "out of scope");
			query_module_close(mod);
			ret = KNOT_EMODINVAL;
			goto activate_error;
		}

		// Check if the module is loadable.
		if (mod->api->load == NULL) {
			MOD_ID_LOG(zone_name, error, mod_id, "empty module, not loaded");
			query_module_close(mod);
			ret = KNOT_EMODINVAL;
			goto activate_error;
		}

		// Load the module.
		ret = mod->api->load(mod);
		if (ret != KNOT_EOK) {
			MOD_ID_LOG(zone_name, error, mod_id, "failed to load (%s)",
			           knot_strerror(ret));
			query_module_close(mod);
			ret = KNOT_EMODINVAL;
			goto activate_error;
		}
		mod->config = NULL; // Invalidate the current config.

		add_tail(query_modules, &mod->node);
		conf_val_next(&val);
	}

	return KNOT_EOK;
activate_error:
	CONF_LOG(LOG_ERR, "failed to activate modules (%s)", knot_strerror(ret));
	conf_deactivate_modules(query_modules, query_plan);
	return ret;
}

void conf_deactivate_modules(
	list_t *query_modules,
	struct query_plan **query_plan)
{
	if (query_modules == NULL || query_plan == NULL) {
		return;
	}

	// Free query plan.
	query_plan_free(*query_plan);
	*query_plan = NULL;

	// Free query modules list.
	knotd_mod_t *mod, *next;
	WALK_LIST_DELSAFE(mod, next, *query_modules) {
		if (mod->api->unload != NULL) {
			mod->api->unload(mod);
		}
		query_module_close(mod);
	}
	init_list(query_modules);
}

void conf_reset_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	if (query_modules == NULL || query_plan == NULL) {
		return;
	}

	struct query_plan *new_plan = query_plan_create();
	if (new_plan == NULL) {
		CONF_LOG(LOG_ERR, "failed to activate modules (%s)", knot_strerror(KNOT_ENOMEM));
		return;
	}

	struct query_plan *old_plan = rcu_xchg_pointer(query_plan, NULL);
	synchronize_rcu();
	query_plan_free(old_plan);

	knotd_mod_t *mod;
	WALK_LIST(mod, *query_modules) {
		if (mod->api->unload != NULL) {
			mod->api->unload(mod);
		}
		query_module_reset(conf, mod, new_plan);
	}

	knotd_mod_t *next;
	WALK_LIST_DELSAFE(mod, next, *query_modules) {
		int ret = mod->api->load(mod);
		if (ret != KNOT_EOK) {
			MOD_ID_LOG(mod->zone, error, mod->id, "failed to load (%s)",
			           knot_strerror(ret));
			rem_node(&mod->node);
			query_module_close(mod);
			continue;
		}
		mod->config = NULL; // Invalidate the current config.
	}

	(void)rcu_xchg_pointer(query_plan, new_plan);
}
