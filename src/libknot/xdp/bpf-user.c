/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknot/endian.h"
#include "libknot/error.h"
#include "libknot/xdp/bpf-kernel-obj.h"
#include "libknot/xdp/bpf-user.h"
#include "libknot/xdp/eth.h"
#include "contrib/openbsd/strlcpy.h"

#define NO_BPF_MAPS	2

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return (ptr == NULL) || (unsigned long)ptr >= (unsigned long)-4095;
}

static int prog_load(struct bpf_object **pobj, int *prog_fd)
{
	struct bpf_program *prog, *first_prog = NULL;
	struct bpf_object *obj;

	obj = bpf_object__open_mem(bpf_kernel_o, bpf_kernel_o_len, NULL);
	if (IS_ERR_OR_NULL(obj)) {
		return KNOT_ENOENT;
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		if (first_prog == NULL) {
			first_prog = prog;
		}
	}

	if (first_prog == NULL) {
		bpf_object__close(obj);
		return KNOT_ENOENT;
	}

	int ret = bpf_object__load(obj);
	if (ret != 0) {
		bpf_object__close(obj);
		return KNOT_EINVAL;
	}

	*pobj = obj;
	*prog_fd = bpf_program__fd(first_prog);

	return KNOT_EOK;
}

static int ensure_prog(struct kxsk_iface *iface, bool overwrite, bool generic_xdp)
{
	if (bpf_kernel_o_len < 2) {
		return KNOT_ENOTSUP;
	}

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall. */
	int prog_fd;
	int ret = prog_load(&iface->prog_obj, &prog_fd);
	if (ret != KNOT_EOK) {
		return KNOT_EPROGRAM;
	}

	uint32_t flags = 0;
	if (!overwrite) {
		flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	}
	if (generic_xdp) {
		flags |= XDP_FLAGS_SKB_MODE;
	}

#if USE_LIBXDP
	ret = bpf_xdp_attach(iface->if_index, prog_fd, flags, NULL);
#else
	ret = bpf_set_link_xdp_fd(iface->if_index, prog_fd, flags);
#endif
	if (ret != 0) {
		close(prog_fd);
	}
	if (ret == -EBUSY && !overwrite) { // We try accepting the present program.
		uint32_t prog_id = 0;
#if USE_LIBXDP
		ret = bpf_xdp_query_id(iface->if_index, 0, &prog_id);
#else
		ret = bpf_get_link_xdp_id(iface->if_index, &prog_id, 0);
#endif
		if (ret == 0 && prog_id != 0) {
			ret = prog_fd = bpf_prog_get_fd_by_id(prog_id);
		}
	}
	if (ret < 0) {
		return KNOT_EFD;
	} else {
		return prog_fd;
	}
}

static void unget_bpf_maps(struct kxsk_iface *iface)
{
	if (iface->opts_map_fd >= 0) {
		close(iface->opts_map_fd);
	}
	if (iface->xsks_map_fd >= 0) {
		close(iface->xsks_map_fd);
	}
	iface->opts_map_fd = iface->xsks_map_fd = -1;
}

/*!
 * /brief Get FDs for the two maps and assign them into xsk_info-> fields.
 *
 * Inspired by xsk_lookup_bpf_maps() from libbpf before qidconf_map elimination.
 */
static int get_bpf_maps(int prog_fd, struct kxsk_iface *iface)
{
	uint32_t *map_ids = calloc(NO_BPF_MAPS, sizeof(*map_ids));
	if (map_ids == NULL) {
		return KNOT_ENOMEM;
	}

	struct bpf_prog_info prog_info = {
		.nr_map_ids = NO_BPF_MAPS,
		.map_ids = (__u64)(unsigned long)map_ids,
	};

	uint32_t prog_len = sizeof(struct bpf_prog_info);
	int ret = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (ret != 0) {
		free(map_ids);
		return ret;
	}

	for (int i = 0; i < NO_BPF_MAPS; ++i) {
		int fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0) {
			continue;
		}

		struct bpf_map_info map_info = { 0 };
		uint32_t map_len = sizeof(struct bpf_map_info);
		ret = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (ret != 0) {
			close(fd);
			continue;
		}

		if (strcmp(map_info.name, "opts_map") == 0) {
			iface->opts_map_fd = fd;
			continue;
		}

		if (strcmp(map_info.name, "xsks_map") == 0) {
			iface->xsks_map_fd = fd;
			continue;
		}

		close(fd);
	}

	if (iface->opts_map_fd < 0 || iface->xsks_map_fd < 0) {
		unget_bpf_maps(iface);
		free(map_ids);
		return KNOT_ENOENT;
	}

	free(map_ids);
	return KNOT_EOK;
}

int kxsk_socket_start(const struct kxsk_iface *iface, knot_xdp_filter_flag_t flags,
                      uint16_t udp_port, uint16_t quic_port, struct xsk_socket *xsk)
{
	if (iface == NULL || xsk == NULL) {
		return KNOT_EINVAL;
	}

	int fd = xsk_socket__fd(xsk);
	int ret = bpf_map_update_elem(iface->xsks_map_fd, &iface->if_queue, &fd, 0);
	if (ret != 0) {
		return ret;
	}

	knot_xdp_opts_t opts = {
		.flags = flags | KNOT_XDP_FILTER_ON,
		.udp_port = udp_port,
		.quic_port = quic_port,
	};

	ret = bpf_map_update_elem(iface->opts_map_fd, &iface->if_queue, &opts, 0);
	if (ret != 0) {
		(void)bpf_map_delete_elem(iface->xsks_map_fd, &iface->if_queue);
	}

	return ret;
}

void kxsk_socket_stop(const struct kxsk_iface *iface)
{
	if (iface == NULL) {
		return;
	}

	knot_xdp_opts_t opts = { 0 };

	(void)bpf_map_update_elem(iface->opts_map_fd, &iface->if_queue, &opts, 0);
	(void)bpf_map_delete_elem(iface->xsks_map_fd, &iface->if_queue);
}

int kxsk_iface_new(const char *if_name, unsigned if_queue, knot_xdp_load_bpf_t load_bpf,
                   bool generic_xdp, struct kxsk_iface **out_iface)
{
	if (if_name == NULL || out_iface == NULL) {
		return KNOT_EINVAL;
	}

	struct kxsk_iface *iface = calloc(1, sizeof(*iface) + IFNAMSIZ);
	if (iface == NULL) {
		return KNOT_ENOMEM;
	}
	iface->if_name = (char *)(iface + 1);
	strlcpy((char *)iface->if_name, if_name, IFNAMSIZ);
	iface->if_index = if_nametoindex(if_name);
	if (iface->if_index == 0) {
		free(iface);
		return KNOT_EINVAL;
	}
	iface->if_queue = if_queue;
	iface->opts_map_fd = iface->xsks_map_fd = -1;

	int ret;
	switch (load_bpf) {
	case KNOT_XDP_LOAD_BPF_NEVER:
		(void)0;
		uint32_t prog_id = 0;
#if USE_LIBXDP
		ret = bpf_xdp_query_id(iface->if_index, 0, &prog_id);
#else
		ret = bpf_get_link_xdp_id(iface->if_index, &prog_id, 0);
#endif
		if (ret == 0) {
			if (prog_id == 0) {
				ret = KNOT_EPROGRAM;
			} else {
				ret = bpf_prog_get_fd_by_id(prog_id);
			}
		}
		break;
	case KNOT_XDP_LOAD_BPF_ALWAYS_UNLOAD:
#if USE_LIBXDP
		(void)bpf_xdp_detach(iface->if_index, 0, NULL);
#else
		(void)bpf_set_link_xdp_fd(iface->if_index, -1, 0);
#endif
		sleep(1);
		// FALLTHROUGH
	case KNOT_XDP_LOAD_BPF_ALWAYS:
		ret = ensure_prog(iface, true, generic_xdp);
		break;
	case KNOT_XDP_LOAD_BPF_MAYBE:
		ret = ensure_prog(iface, false, generic_xdp);
		break;
	default:
		return KNOT_EINVAL;
	}

	if (ret >= 0) {
		ret = get_bpf_maps(ret, iface);
	}
	if (ret < 0) {
		kxsk_iface_free(iface);
		return ret;
	}

	knot_xdp_mode_t mode = knot_eth_xdp_mode(iface->if_index);
	if (mode == KNOT_XDP_MODE_NONE) {
		kxsk_iface_free(iface);
		return KNOT_ENOTSUP;
	}

	*out_iface = iface;
	return KNOT_EOK;
}

void kxsk_iface_free(struct kxsk_iface *iface)
{
	if (iface == NULL) {
		return;
	}

	unget_bpf_maps(iface);

	if (iface->prog_obj != NULL) {
		bpf_object__close(iface->prog_obj);
	}

	free(iface);
}
