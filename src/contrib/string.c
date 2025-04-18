/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_EXPLICIT_BZERO)
  #if defined(HAVE_BSD_STRING_H)
    #include <bsd/string.h>
  #endif
  /* #include <string.h> is needed. */
#elif defined(HAVE_EXPLICIT_MEMSET)
  /* #include <string.h> is needed. */
#else
  #include <gnutls/gnutls.h>
#endif

#include "contrib/string.h"
#include "contrib/ctype.h"
#include "contrib/tolower.h"

const char *configure_summary = CONFIGURE_SUMMARY;

uint8_t *memdup(const uint8_t *data, size_t data_size)
{
	uint8_t *result = (uint8_t *)malloc(data_size);
	if (!result) {
		return NULL;
	}

	return memcpy(result, data, data_size);
}

int strmemcmp(const char *str, const uint8_t *mem, size_t mem_size)
{
	if (mem_size == 0) {
		return 1;
	}
	size_t cmp_len = strnlen(str, mem_size - 1) + 1;
	return memcmp(str, mem, cmp_len);
}

char *sprintf_alloc(const char *fmt, ...)
{
	char *strp = NULL;
	va_list ap;

	va_start(ap, fmt);
	int ret = vasprintf(&strp, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		return NULL;
	}
	return strp;
}

char *strcdup(const char *s1, const char *s2)
{
	if (!s1 || !s2) {
		return NULL;
	}

	size_t s1len = strlen(s1);
	size_t s2len = strlen(s2);
	size_t nlen = s1len + s2len + 1;

	char* dst = malloc(nlen);
	if (dst == NULL) {
		return NULL;
	}

	memcpy(dst, s1, s1len);
	memcpy(dst + s1len, s2, s2len + 1);
	return dst;
}

char *strstrip(const char *str)
{
	// leading white-spaces
	const char *scan = str;
	while (is_space(scan[0])) {
		scan += 1;
	}

	// trailing white-spaces
	size_t len = strlen(scan);
	while (len > 0 && is_space(scan[len - 1])) {
		len -= 1;
	}

	char *trimmed = malloc(len + 1);
	if (!trimmed) {
		return NULL;
	}

	memcpy(trimmed, scan, len);
	trimmed[len] = '\0';

	return trimmed;
}

void strtolower(char *str)
{
	if (str == NULL) {
		return;
	}

	for (char *it = str; *it != '\0'; ++it) {
		*it = knot_tolower(*it);
	}
}

int const_time_memcmp(const void *s1, const void *s2, size_t n)
{
	volatile uint8_t equal = 0;

	for (size_t i = 0; i < n; i++) {
		equal |= ((uint8_t *)s1)[i] ^ ((uint8_t *)s2)[i];
	}

	return equal;
}

void *memzero(void *s, size_t n)
{
#if defined(HAVE_EXPLICIT_BZERO)	/* In OpenBSD since 5.5. */
					/* In FreeBSD since 11.0. */
					/* In glibc since 2.25. */
					/* In DragonFly BSD since 5.5. */
#  if defined(__has_feature)
#    if __has_feature(memory_sanitizer)
	#warning "Memory sanitizer detected. Using bzero() instead of explicit_bzero()."
	bzero(s, n);
#    else
	explicit_bzero(s, n);
#    endif
#  else
	explicit_bzero(s, n);
#  endif
	return s;
#elif defined(HAVE_EXPLICIT_MEMSET)	/* In NetBSD since 7.0. */
	return explicit_memset(s, 0, n);
#else
	gnutls_memset(s, 0, n);
	return s;
#endif
}

static const char BIN_TO_HEX[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

char *bin_to_hex(const uint8_t *bin, size_t bin_len, bool upper_case)
{
	if (bin == NULL) {
		return NULL;
	}

	size_t hex_size = bin_len * 2;
	char *hex = malloc(hex_size + 1);
	if (hex == NULL) {
		return NULL;
	}

	unsigned offset = upper_case ? 16 : 0;
	for (size_t i = 0; i < bin_len; i++) {
		hex[2 * i]     = BIN_TO_HEX[offset + (bin[i] >> 4)];
		hex[2 * i + 1] = BIN_TO_HEX[offset + (bin[i] & 0x0f)];
	}
	hex[hex_size] = '\0';

	return hex;
}

/*!
 * Convert HEX character to numeric value (assumes valid input).
 */
static uint8_t hex_to_number(const char hex)
{
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	} else if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10;
	} else {
		assert(hex >= 'A' && hex <= 'F');
		return hex - 'A' + 10;
	}
}

uint8_t *hex_to_bin(const char *hex, size_t *out_len)
{
	if (hex == NULL || out_len == NULL) {
		return NULL;
	}

	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0) {
		return NULL;
	}

	size_t bin_len = hex_len / 2;
	uint8_t *bin = malloc(bin_len + 1);
	if (bin == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < bin_len; i++) {
		if (!is_xdigit(hex[2 * i]) || !is_xdigit(hex[2 * i + 1])) {
			free(bin);
			return NULL;
		}
		uint8_t high = hex_to_number(hex[2 * i]);
		uint8_t low  = hex_to_number(hex[2 * i + 1]);
		bin[i] = high << 4 | low;
	}

	*out_len = bin_len;

	return bin;
}
