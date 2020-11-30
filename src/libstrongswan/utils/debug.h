/*
 * Copyright (C) 2006 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup debug debug
 * @{ @ingroup utils
 */

#ifndef DEBUG_H_
#define DEBUG_H_

typedef enum debug_t debug_t;
typedef enum level_t level_t;

#include <utils/printf_hook/printf_hook.h>
#include <utils/utils.h>
#include <stdio.h>

#include <threading/mutex.h>
#include <unistd.h>
#include <utils/utils/types.h>

mutex_t *wataash_debug_mutex;

/**
 * Debug message group.
 */
enum debug_t {
	/** daemon specific */
	DBG_DMN,
	/** IKE_SA_MANAGER */
	DBG_MGR,
	/** IKE_SA */
	DBG_IKE,
	/** CHILD_SA */
	DBG_CHD,
	/** job processing */
	DBG_JOB,
	/** configuration backends */
	DBG_CFG,
	/** kernel interface */
	DBG_KNL,
	/** networking/sockets */
	DBG_NET,
	/** low-level encoding/decoding (ASN.1, X.509 etc.) */
	DBG_ASN,
	/** message encoding/decoding */
	DBG_ENC,
	/** trusted network connect */
	DBG_TNC,
	/** integrity measurement client */
	DBG_IMC,
	/** integrity measurement verifier */
	DBG_IMV,
	/** platform trust service */
	DBG_PTS,
	/** libtls */
	DBG_TLS,
	/** applications other than daemons */
	DBG_APP,
	/** libipsec */
	DBG_ESP,
	/** libstrongswan */
	DBG_LIB,
	/** number of groups */
	DBG_MAX,
	/** pseudo group with all groups */
	DBG_ANY = DBG_MAX,
};

/**
 * short names of debug message group.
 */
extern enum_name_t *debug_names;

/**
 * short names of debug message group, lower case.
 */
extern enum_name_t *debug_lower_names;

/**
 * Debug levels used to control output verbosity.
 */
enum level_t {
	/** absolutely silent */
	LEVEL_SILENT = -1,
	/** most important auditing logs */
	LEVEL_AUDIT =   0,
	/** control flow */
	LEVEL_CTRL =    1,
	/** diagnose problems */
	LEVEL_DIAG =    2,
	/** raw binary blobs */
	LEVEL_RAW =     3,
	/** including sensitive data (private keys) */
	LEVEL_PRIVATE = 4,
};

#ifndef DEBUG_LEVEL
# define DEBUG_LEVEL 4
#endif /* DEBUG_LEVEL */

#undef DEBUG_LEVEL
#define DEBUG_LEVEL 9

// DBG0 LEVEL_AUDIT       error
// DBG1 LEVEL_CTRL        warn
// DBG2 LEVEL_DIAG        info
// DBG3 LEVEL_RAW         debug
// DBG4 LEVEL_PRIVATE     trace

/** debug macros, they call the dbg function hook */
#if DEBUG_LEVEL >= 0
# define DBG0(group, fmt, ...) dbg(group, 0, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 1
# define DBG1(group, fmt, ...) dbg(group, 1, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 2
# define DBG2(group, fmt, ...) dbg(group, 2, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 3
# define DBG3(group, fmt, ...) dbg(group, 3, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 4
# define DBG4(group, fmt, ...) dbg(group, 4, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */

#ifndef DBG0
# define DBG0(...) {}
#endif
#ifndef DBG1
# define DBG1(...) {}
#endif
#ifndef DBG2
# define DBG2(...) {}
#endif
#ifndef DBG3
# define DBG3(...) {}
#endif
#ifndef DBG4
# define DBG4(...) {}
#endif

/** dbg function hook, uses dbg_default() by default */
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

/** default logging function */
void dbg_default(debug_t group, level_t level, char *fmt, ...);

/** set the level logged by dbg_default() */
void dbg_default_set_level(level_t level);

/** set the stream logged by dbg_default() to */
void dbg_default_set_stream(FILE *stream);

static inline void wataash_debug_lock(void)
{
	// return;

	// slow, and unstable?
	if (wataash_debug_mutex == NULL)
		wataash_debug_mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	wataash_debug_mutex->lock(wataash_debug_mutex);

}

static inline void wataash_debug_unlock(void)
{
	// return;
	wataash_debug_mutex->unlock(wataash_debug_mutex);
}

static inline void wataash_debug_reset(void)
{
	fprintf(stderr, "\x1b[0m");
}

enum wataash_debug_kind {
	WATAASH_DEBUG_KIND_NONE,
	WATAASH_DEBUG_KIND_ANY,
	WATAASH_DEBUG_KIND_APP,
	WATAASH_DEBUG_KIND_LIB,
};

static inline void wataash_debug(debug_t group, level_t level, enum wataash_debug_kind kind)
{
	{
		timeval_t tv;
		static timeval_t tv_prev = {.tv_sec = 0, .tv_usec = 0};
		if (tv_prev.tv_sec == 0 && tv_prev.tv_usec == 0)
			time_monotonic(&tv_prev);
		time_monotonic(&tv);
		timeval_t tv_sub;
		timersub(&tv, &tv_prev, &tv_sub);
		static const timeval_t tv100ms = {.tv_sec = 0, .tv_usec = 100000};
		if (timercmp(&tv_sub, &tv100ms, >))
			fprintf(stderr, "\n");
		tv_prev = tv;
	}

	// vvvvvvvv   毎回色ランダムなのびみょい
	//          v 0 は真っ黒で見えない
	// 01482144 00 R00[LIB] loading feature SIGNER:HMAC_SHA1_160 in plugin 'hmac' 01482144 15 D15[JOB] started worker thread 15
	//          ^^  ^^ 被ってる
#if 0
	pid_t pid = getpid();
		u_int tid = thread_current_id();
		fprintf(stderr, "\x1b[38;5;%um%08jd \x1b[38;5;%um%02u ", (u_int)pid % 256, (intmax_t)pid, tid % 256, tid);
#endif

#if 0
	static struct {
			pid_t pid;
			const char *const esc;
		} color_map[] = {
			{0, "\x1b[0m"},
			{0, "\x1b[37m"},
			{-1, NULL},
			{-2, "\x1b[31m"},
		};
		pid_t pid = getpid();
		size_t i_map;
		for (i_map = 0; /* i_map < countof(color_map) */; i_map++) {
			if (color_map[i_map].pid == pid)
				break;
			if (color_map[i_map].pid == 0) {
				color_map[i_map].pid = pid;
				break;
			}
			if (color_map[i_map].esc == NULL) {
				i_map = countof(color_map) - 1;
			}
		}
		fprintf(stderr, "%s%08jd ", color_map[i_map].esc, (intmax_t)pid);
#endif

	//

	extern const char *__progname;
	struct prog_esc {
		const char *const progname;
		const char *const esc;
	};
	const struct prog_esc *const prog_esc_list[] = {
		(const struct prog_esc *const) &(const struct prog_esc){"starter", "\x1b[0m"},
		(const struct prog_esc *const) &(const struct prog_esc){"charon", "\x1b[37m"},
		NULL,
	};
	const char *esc = "\x1b[31m";
	for (const struct prog_esc *const *p = prog_esc_list; *p != NULL; p++) {
		if (strcmp((*p)->progname, __progname) == 0) {
			esc = (*p)->esc;
			break;
		}
	}
	fprintf(stderr, "%s%08jd ", esc, (intmax_t)getpid());

	if (FALSE) {}
	else if (level == LEVEL_SILENT)  fprintf(stderr, "\x1b[31m"); // red
	else if (level == LEVEL_AUDIT)   fprintf(stderr, "\x1b[33m"); // yellow
	else if (level == LEVEL_CTRL)    fprintf(stderr, "\x1b[34m"); // blue
	else if (level == LEVEL_DIAG)    fprintf(stderr, "\x1b[0m"); // normal
	else if (level == LEVEL_RAW)     fprintf(stderr, "\x1b[37m"); // white
	// else if (level == LEVEL_PRIVATE) fprintf(stderr, "\x1b[47m"); // back white
	else if (level == LEVEL_PRIVATE) fprintf(stderr, "\x1b[37m"); // white
	else fprintf(stderr, "\x1b[43m"); // back yellow

	static u_int seq;
	fprintf(stderr, "%06u L%d ", seq, level);
	seq++;

	if (FALSE) {
	} else if (kind == WATAASH_DEBUG_KIND_NONE) {
	} else if (kind == WATAASH_DEBUG_KIND_ANY) {
		if (FALSE) {}
		else if (group == DBG_DMN) fprintf(stderr, "[DMN] ");
		else if (group == DBG_MGR) fprintf(stderr, "[MGR] ");
		else if (group == DBG_IKE) fprintf(stderr, "[IKE] ");
		else if (group == DBG_CHD) fprintf(stderr, "[CHD] ");
		else if (group == DBG_JOB) fprintf(stderr, "[JOB] ");
		else if (group == DBG_CFG) fprintf(stderr, "[CFG] ");
		else if (group == DBG_KNL) fprintf(stderr, "[KNL] ");
		else if (group == DBG_NET) fprintf(stderr, "[NET] ");
		else if (group == DBG_ASN) fprintf(stderr, "[ASN] ");
		else if (group == DBG_ENC) fprintf(stderr, "[ENC] ");
		else if (group == DBG_TNC) fprintf(stderr, "[TNC] ");
		else if (group == DBG_IMC) fprintf(stderr, "[IMC] ");
		else if (group == DBG_IMV) fprintf(stderr, "[IMV] ");
		else if (group == DBG_PTS) fprintf(stderr, "[PTS] ");
		else if (group == DBG_TLS) fprintf(stderr, "[TLS] ");
		else if (group == DBG_APP) fprintf(stderr, "[APP] ");
		else if (group == DBG_ESP) fprintf(stderr, "[ESP] ");
		else if (group == DBG_LIB) fprintf(stderr, "[LIB] ");
		// else if (group == DBG_MAX) fprintf(stderr, "[MAX] ");
		else if (group == DBG_ANY) fprintf(stderr, "[ANY] ");
		else fprintf(stderr, "\x1b[31m[!!!???] ");
	} else if (kind == WATAASH_DEBUG_KIND_APP) {
		if (FALSE) {}
		else if (group == DBG_DMN) fprintf(stderr, "\x1b[31m[!!!DMN] ");
		else if (group == DBG_MGR) fprintf(stderr, "\x1b[31m[!!!MGR] ");
		else if (group == DBG_IKE) fprintf(stderr, "\x1b[31m[!!!IKE] ");
		else if (group == DBG_CHD) fprintf(stderr, "\x1b[31m[!!!CHD] ");
		else if (group == DBG_JOB) fprintf(stderr, "\x1b[31m[!!!JOB] ");
		else if (group == DBG_CFG) fprintf(stderr, "\x1b[31m[!!!CFG] ");
		else if (group == DBG_KNL) fprintf(stderr, "\x1b[31m[!!!KNL] ");
		else if (group == DBG_NET) fprintf(stderr, "\x1b[31m[!!!NET] ");
		else if (group == DBG_ASN) fprintf(stderr, "\x1b[31m[!!!ASN] ");
		else if (group == DBG_ENC) fprintf(stderr, "\x1b[31m[!!!ENC] ");
		else if (group == DBG_TNC) fprintf(stderr, "\x1b[31m[!!!TNC] ");
		else if (group == DBG_IMC) fprintf(stderr, "\x1b[31m[!!!IMC] ");
		else if (group == DBG_IMV) fprintf(stderr, "\x1b[31m[!!!IMV] ");
		else if (group == DBG_PTS) fprintf(stderr, "\x1b[31m[!!!PTS] ");
		else if (group == DBG_TLS) fprintf(stderr, "\x1b[31m[!!!TLS] ");
		else if (group == DBG_APP) fprintf(stderr, "[APP] ");
		else if (group == DBG_ESP) fprintf(stderr, "\x1b[31m[!!!ESP] ");
		else if (group == DBG_LIB) fprintf(stderr, "\x1b[31m[!!!LIB] ");
		// else if (group == DBG_MAX) fprintf(stderr, "\x1b[31m[!!!MAX] ");
		else if (group == DBG_ANY) fprintf(stderr, "\x1b[31m[!!!ANY] ");
		else fprintf(stderr, "\x1b[31m[!!!???] ");
	} else if (kind == WATAASH_DEBUG_KIND_LIB) {
		if (FALSE) {}
		else if (group == DBG_DMN) fprintf(stderr, "\x1b[31m[!!!DMN] ");
		else if (group == DBG_MGR) fprintf(stderr, "\x1b[31m[!!!MGR] ");
		else if (group == DBG_IKE) fprintf(stderr, "\x1b[31m[!!!IKE] ");
		else if (group == DBG_CHD) fprintf(stderr, "\x1b[31m[!!!CHD] ");
		else if (group == DBG_JOB) fprintf(stderr, "\x1b[31m[!!!JOB] ");
		else if (group == DBG_CFG) fprintf(stderr, "\x1b[31m[!!!CFG] ");
		else if (group == DBG_KNL) fprintf(stderr, "\x1b[31m[!!!KNL] ");
		else if (group == DBG_NET) fprintf(stderr, "\x1b[31m[!!!NET] ");
		else if (group == DBG_ASN) fprintf(stderr, "\x1b[31m[!!!ASN] ");
		else if (group == DBG_ENC) fprintf(stderr, "\x1b[31m[!!!ENC] ");
		else if (group == DBG_TNC) fprintf(stderr, "\x1b[31m[!!!TNC] ");
		else if (group == DBG_IMC) fprintf(stderr, "\x1b[31m[!!!IMC] ");
		else if (group == DBG_IMV) fprintf(stderr, "\x1b[31m[!!!IMV] ");
		else if (group == DBG_PTS) fprintf(stderr, "\x1b[31m[!!!PTS] ");
		else if (group == DBG_TLS) fprintf(stderr, "\x1b[31m[!!!TLS] ");
		else if (group == DBG_APP) fprintf(stderr, "\x1b[31m[!!!APP] ");
		else if (group == DBG_ESP) fprintf(stderr, "\x1b[31m[!!!ESP] ");
		else if (group == DBG_LIB) fprintf(stderr, "[LIB] ");
		// else if (group == DBG_MAX) fprintf(stderr, "\x1b[31m[!!!MAX] ");
		else if (group == DBG_ANY) fprintf(stderr, "\x1b[31m[!!!ANY] ");
		else fprintf(stderr, "\x1b[31m[!!!???] ");
	} else {
		fprintf(stderr, "\x1b[31m[!!!??????] ");
	}
}

#endif /** DEBUG_H_ @}*/
