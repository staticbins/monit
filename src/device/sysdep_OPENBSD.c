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

/**
 *  System dependent filesystem methods.
 *
 *  @file
 */

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_DISK_H
#include <sys/disk.h>
#endif

#include "monit.h"
#include "device.h"

// libmonit
#include "system/Time.h"
#include "io/File.h"


/* ------------------------------------------------------------- Definitions */


static struct {
        unsigned long long timestamp;
        size_t diskCount;
        size_t diskLength;
        struct diskstats *disk;
} _statistics = {};


/* ------------------------------------------------------- Static destructor */


static void __attribute__ ((destructor)) _destructor() {
        FREE(_statistics.disk);
}


/* ----------------------------------------------------------------- Private */


static unsigned long long _timevalToMilli(struct timeval *time) {
        return time->tv_sec * 1000 + time->tv_usec / 1000.;
}


// Parse the device path like /dev/sd0a -> sd0
static bool _parseDevice(const char *path, Device_T device) {
        const char *base = File_basename(path);
        for (ssize_t len = strlen(base), i = len - 1; i >= 0; i--) {
                if (isdigit(*(base + i))) {
                        strncpy(device->key, base, i + 1 < (ssize_t)sizeof(device->key) ? i + 1 : (ssize_t)sizeof(device->key) - 1);
                        return true;
                }
        }
        return false;
}


static bool _getStatistics(unsigned long long now) {
        // Refresh only if the statistics are older then 1 second (handle also backward time jumps)
        if (now > _statistics.timestamp + 1000 || now < _statistics.timestamp - 1000) {
                ssize_t len = sizeof(_statistics.diskCount);
                int mib[2] = {CTL_HW, HW_DISKCOUNT};
                if (sysctl(mib, 2, &(_statistics.diskCount), &len, NULL, 0) == -1) {
                        LogError("filesystem statistic error -- cannot get disks count: %s\n", STRERROR);
                        return false;
                }
                len = _statistics.diskCount * sizeof(struct diskstats);
                if ((ssize_t)_statistics.diskLength != len) {
                        _statistics.diskLength = len;
                        RESIZE(_statistics.disk, len);
                }
                mib[1] = HW_DISKSTATS;
                if (sysctl(mib, 2, _statistics.disk, &(_statistics.diskLength), NULL, 0) == -1) {
                        LogError("filesystem statistic error -- cannot get disks statistics: %s\n", STRERROR);
                        return false;
                }
                _statistics.timestamp = now;
        }
        return true;
}


static bool _getDummyDiskActivity(__attribute__ ((unused)) void *_inf) {
        return true;
}


static bool _getBlockDiskActivity(void *_inf) {
        Info_T inf = _inf;
        unsigned long long now = Time_milli();
        bool rv = _getStatistics(now);
        if (rv) {
                for (size_t i = 0; i < _statistics.diskCount; i++)     {
                        if (Str_isEqual(inf->filesystem->object.key, _statistics.disk[i].ds_name)) {
                                Statistics_update(&(inf->filesystem->read.bytes), now, _statistics.disk[i].ds_rbytes);
                                Statistics_update(&(inf->filesystem->write.bytes), now, _statistics.disk[i].ds_wbytes);
                                Statistics_update(&(inf->filesystem->read.operations),  now, _statistics.disk[i].ds_rxfer);
                                Statistics_update(&(inf->filesystem->write.operations), now, _statistics.disk[i].ds_wxfer);
                                Statistics_update(&(inf->filesystem->time.run), now, _timevalToMilli(&(_statistics.disk[i].ds_time)));
                                break;
                        }
                }
        }
        return rv;
}


static bool _getDiskUsage(void *_inf) {
        Info_T inf = _inf;
        struct statfs usage;
        if (statfs(inf->filesystem->object.mountpoint, &usage) != 0) {
                LogError("Error getting usage statistics for filesystem '%s' -- %s\n", inf->filesystem->object.mountpoint, STRERROR);
                return false;
        }
        inf->filesystem->f_bsize = usage.f_bsize;
        inf->filesystem->f_blocks = usage.f_blocks;
        inf->filesystem->f_blocksfree = usage.f_bavail;
        inf->filesystem->f_blocksfreetotal = usage.f_bfree;
        inf->filesystem->f_files = usage.f_files;
        inf->filesystem->f_filesfree = usage.f_ffree;
        return true;
}


static bool _compareMountpoint(const char *mountpoint, struct statfs *mnt) {
        return IS(mountpoint, mnt->f_mntonname);
}


static bool _compareDevice(const char *device, struct statfs *mnt) {
        return IS(device, mnt->f_mntfromname);
}


static void _filesystemFlagsToString(Info_T inf, unsigned long long flags) {
        struct mystable {
                unsigned long long flag;
                char *description;
        } t[]= {
                {MNT_RDONLY, "ro"},
                {MNT_SYNCHRONOUS, "synchronous"},
                {MNT_NOEXEC, "noexec"},
                {MNT_NOSUID, "nosuid"},
                {MNT_NODEV, "nodev"},
                {MNT_WXALLOWED, "wxallowed"},
                {MNT_ASYNC, "async"},
                {MNT_NOATIME, "noatime"},
                {MNT_EXRDONLY, "exported read only"},
                {MNT_EXPORTED, "exported"},
                {MNT_DEFEXPORTED, "exported to the world"},
                {MNT_EXPORTANON, "anon uid mapping"},
                {MNT_LOCAL, "local"},
                {MNT_QUOTA, "quota"},
                {MNT_ROOTFS, "rootfs"}
        };
        for (size_t i = 0, count = 0; i < sizeof(t) / sizeof(t[0]); i++) {
                if (flags & t[i].flag) {
                        snprintf(inf->filesystem->flags + strlen(inf->filesystem->flags), sizeof(inf->filesystem->flags) - strlen(inf->filesystem->flags) - 1, "%s%s", count++ ? ", " : "", t[i].description);
                }
        }
}


static bool _setDevice(Info_T inf, const char *path, bool (*compare)(const char *path, struct statfs *mnt)) {
        int countfs = getfsstat(NULL, 0, MNT_NOWAIT);
        if (countfs != -1) {
                struct statfs *mnt = CALLOC(countfs, sizeof(struct statfs));
                if ((countfs = getfsstat(mnt, countfs * sizeof(struct statfs), MNT_NOWAIT)) != -1) {
                        for (int i = 0; i < countfs; i++) {
                                struct statfs *mntItem = mnt + i;
                                if (compare(path, mntItem)) {
                                        if (IS(mntItem->f_fstypename, "ffs")) {
                                                if (_parseDevice(mntItem->f_mntfromname, &(inf->filesystem->object))) {
                                                        inf->filesystem->object.getDiskActivity = _getBlockDiskActivity;
                                                } else {
                                                        inf->filesystem->object.getDiskActivity = _getDummyDiskActivity;
                                                        DEBUG("I/O monitoring for filesystem '%s' skipped - unable to parse the device %s", path, mntItem->f_mntfromname);
                                                }
                                        } else {
                                                inf->filesystem->object.getDiskActivity = _getDummyDiskActivity;
                                        }
                                        if ((mntItem->f_flags & MNT_VISFLAGMASK) != inf->filesystem->object.flags) {
                                                if (inf->filesystem->object.flags) {
                                                        inf->filesystem->flagsChanged = true;
                                                }
                                                inf->filesystem->object.flags = mntItem->f_flags & MNT_VISFLAGMASK;
                                                _filesystemFlagsToString(inf, inf->filesystem->object.flags);
                                        }
                                        strncpy(inf->filesystem->object.device, mntItem->f_mntfromname, sizeof(inf->filesystem->object.device) - 1);
                                        strncpy(inf->filesystem->object.mountpoint, mntItem->f_mntonname, sizeof(inf->filesystem->object.mountpoint) - 1);
                                        strncpy(inf->filesystem->object.type, mntItem->f_fstypename, sizeof(inf->filesystem->object.type) - 1);
                                        inf->filesystem->object.getDiskUsage = _getDiskUsage;
                                        inf->filesystem->object.mounted = true;
                                        FREE(mnt);
                                        return true;
                                }
                        }
                }
                FREE(mnt);
        }
        LogError("Lookup for '%s' filesystem failed\n", path);
error:
        inf->filesystem->object.mounted = false;
        return false;
}


static bool _getDevice(Info_T inf, const char *path, bool (*compare)(const char *path, struct statfs *mnt)) {
        if (_setDevice(inf, path, compare)) {
                return (inf->filesystem->object.getDiskUsage(inf) && inf->filesystem->object.getDiskActivity(inf));
        }
        return false;
}


/* ------------------------------------------------------------------ Public */


bool Filesystem_getByMountpoint(Info_T inf, const char *path) {
        ASSERT(inf);
        ASSERT(path);
        return _getDevice(inf, path, _compareMountpoint);
}


bool Filesystem_getByDevice(Info_T inf, const char *path) {
        ASSERT(inf);
        ASSERT(path);
        return _getDevice(inf, path, _compareDevice);
}

