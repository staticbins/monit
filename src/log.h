/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.
 */


#ifndef LOG_INCLUDED
#define LOG_INCLUDED

bool log_init(void);
void LogEmergency(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogAlert(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogCritical(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogError(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogWarning(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogNotice(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogInfo(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogDebug(const char *, ...) __attribute__((format (printf, 1, 2)));
void LogAbort(const char *s, ...) __attribute__((format (printf, 1, 2)));
void vLogEmergency(const char *, va_list ap);
void vLogAlert(const char *, va_list ap);
void vLogCritical(const char *, va_list ap);
void vLogError(const char *, va_list ap);
void vLogWarning(const char *,va_list ap);
void vLogNotice(const char *, va_list ap);
void vLogInfo(const char *, va_list ap);
void vLogDebug(const char *, va_list ap);
void vLogAbort(const char *s, va_list ap);
void log_close(void);
#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
void vsyslog (int, const char *, va_list);
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */

#endif /* LOG_INCLUDED */
