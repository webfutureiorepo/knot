/*!
 * \file log.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Logging facility.
 *
 * \note Loglevel defined in syslog.h, may be redefined in other backend, but
 * keep naming. LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG
 *
 * In standard mode, only LOG_ERR and LOG_WARNING is displayed and logged.
 * Verbose mode enables LOG_NOTICE and LOG_INFO for additional information.
 *
 * \addtogroup logging
 * @{
 */
#ifndef _CUTEDNS_LOG_H_
#define _CUTEDNS_LOG_H_

/*
 */
#include <syslog.h>
#include <stddef.h>
#include <stdint.h>

/*! \brief Log facility types. */
typedef enum {
	LOGT_SYSLOG = 0, /*!< Logging to syslog(3) facility. */
	LOGT_STDERR = 1, /*!< Print log messages to the stderr. */
	LOGT_STDOUT = 2, /*!< Print log messages to the stdout. */
	LOGT_FILE   = 3  /*!< Generic logging to (unbuffered) file on the disk. */
} logtype_t;

/*! \brief Log sources width (bits). */
#define LOG_SRC_BITS 3

/*! \brief Log sources (max. LOG_SRC_BITS bits). */
typedef enum {
	LOG_SERVER = 0, /*!< Server module. */
	LOG_ANSWER = 1, /*!< Query answering module. */
	LOG_ZONE   = 2, /*!< Zone manipulation module. */
	LOG_ANY    = 7  /*!< Any module. */
} logsrc_t;

/* Logging facility setup. */

/*!
 * \brief Create logging facilities respecting their
 *        canonical order.
 *
 * Facilities ordering: Syslog, Stderr, Stdout, File0...
 * \see logtype_t
 *
 * \param facilities Number of requested facilities.
 *
 * \retval 0 On success.
 * \retval <0 If an error occured.
 */
int log_setup(int facilities);

/*!
 * \brief Setup logging subsystem.
 *
 * \see syslog.h
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_init();

/*!
 * \brief Close and deinitialize log.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int log_close();

/*!
 * \brief Truncate current log setup.
 */
void log_truncate();

/*!
 * \brief Return positive number if open.
 *
 * \return 1 if open (boolean true)
 * \return 0 if closed (boolean false)
 */
int log_isopen();

/*!
 * \brief Open file as a logging facility.
 *
 * \param filename File path.
 *
 * \retval associated facility index on success.
 * \retval <0 on error.
 */
int log_open_file(const char* filename);

/*!
 * \brief Return log levels for a given facility.
 *
 * \param facility Given log facility index.
 * \param src Given log source in the context of current facility.
 *
 * \retval Associated log level flags on success.
 * \retval 0 on error.
 */
uint8_t log_levels(int facility, logsrc_t src);

/*!
 * \brief Set log levels for given facility.
 *
 * \param facility Logging facility index (LOGT_SYSLOG...).
 * \param src Logging source (LOG_SERVER...LOG_ANY).
 * \param levels Bitmask of specified log levels.
 *
 * \retval 0 On success.
 * \retval <0 On error.
 */
int log_levels_set(int facility, logsrc_t src, uint8_t levels);

/*!
 * \brief Add log levels to a given facility.
 *
 * New levels are added on top of existing, the resulting
 * levels set is "old_levels OR new_levels".
 *
 * \param facility Logging facility index (LOGT_SYSLOG...).
 * \param src Logging source (LOG_SERVER...LOG_ANY).
 * \param levels Bitmask of specified log levels.
 *
 * \retval 0 On success.
 * \retval <0 On error.
 */
int log_levels_add(int facility, logsrc_t src, uint8_t levels);

/* Logging functions. */
int print_msg(int level, const char *msg, ...) __attribute__((format(printf, 2, 3)));

#define log_msg(level, msg...) \
	do { \
	if(log_isopen()) { \
		syslog((level), msg); \
	} \
	print_msg((level), msg); \
	} while (0)

/* Convenient logging. */
#define log_error(msg...)     log_msg(LOG_ERR, msg)
#define log_warning(msg...)   log_msg(LOG_WARNING, msg)
#define log_notice(msg...)    log_msg(LOG_NOTICE, msg)
#define log_info(msg...)      log_msg(LOG_INFO, msg)
#define log_debug(msg...)     log_msg(LOG_DEBUG, msg)

#endif /* _CUTEDNS_LOG_H_ */

/*! @} */
