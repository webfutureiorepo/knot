/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup error
 *
 * \brief Error codes and error reporting.
 *
 * The module defines all error codes used in the library, and functions
 * to convert the error codes to sensible error strings.
 *
 * @{
 */

#pragma once

#include <errno.h>

/*!
 * Library error codes.
 */
enum dnssec_error {
	DNSSEC_EOK = 0,

	DNSSEC_ENOMEM = -ENOMEM,
	DNSSEC_EINVAL = -EINVAL,
	DNSSEC_ENOENT = -ENOENT,

	DNSSEC_ERROR_MIN = -1500,

	DNSSEC_ERROR = DNSSEC_ERROR_MIN,
	DNSSEC_NOT_IMPLEMENTED_ERROR,
	DNSSEC_MALFORMED_DATA,
	DNSSEC_NOT_FOUND,

	DNSSEC_PKCS8_IMPORT_ERROR,
	DNSSEC_KEY_EXPORT_ERROR,
	DNSSEC_KEY_IMPORT_ERROR,
	DNSSEC_KEY_GENERATE_ERROR,

	DNSSEC_INVALID_PUBLIC_KEY,
	DNSSEC_INVALID_PRIVATE_KEY,
	DNSSEC_INVALID_KEY_ALGORITHM,
	DNSSEC_INVALID_KEY_SIZE,
	DNSSEC_INVALID_KEY_ID,
	DNSSEC_INVALID_KEY_NAME,

	DNSSEC_NO_PUBLIC_KEY,
	DNSSEC_NO_PRIVATE_KEY,
	DNSSEC_KEY_ALREADY_PRESENT,

	DNSSEC_SIGN_INIT_ERROR,
	DNSSEC_SIGN_ERROR,
	DNSSEC_INVALID_SIGNATURE,

	DNSSEC_INVALID_NSEC3_ALGORITHM,
	DNSSEC_NSEC3_HASHING_ERROR,

	DNSSEC_INVALID_DS_ALGORITHM,
	DNSSEC_DS_HASHING_ERROR,

	DNSSEC_KEYSTORE_INVALID_CONFIG,

	DNSSEC_P11_FAILED_TO_LOAD_MODULE,
	DNSSEC_P11_TOO_MANY_MODULES,
	DNSSEC_P11_TOKEN_NOT_AVAILABLE,

	DNSSEC_INVALID_DIGEST_ALGORITHM,
	DNSSEC_DIGEST_ERROR,

	DNSSEC_ERROR_MAX = -1001
};

/*!
 * Translate error code to error message.
 *
 * \param error  Error code.
 *
 * \return Statically allocated error message string or NULL if unknown.
 */
const char *dnssec_strerror(int error);

/*!
 * Convert errno value to DNSSEC error code.
 */
static inline int dnssec_errno_to_error(int ecode)
{
	return -ecode;
}

/*! @} */
