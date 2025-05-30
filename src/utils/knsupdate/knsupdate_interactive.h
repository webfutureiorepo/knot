/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/knsupdate/knsupdate_params.h"

/*!
 * Executes an interactive processing loop.
 *
 * \param[in] params  Utility parameters.
 */
int interactive_loop(knsupdate_params_t *params);
