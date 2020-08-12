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

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#include "monit.h"
#include "device.h"

// libmonit
#include "io/File.h"
#include "system/Time.h"
#include "exceptions/AssertException.h"


/* ------------------------------------------------------------- Definitions */


#define MOUNTS   "/proc/self/mounts"
#define CIFSSTAT "/proc/fs/cifs/Stats"
#define DISKSTAT "/proc/diskstats"
#define NFSSTAT  "/proc/self/mountstats"


static struct {
        int fd;                                    // /proc/self/mounts filedescriptor (needed for mount/unmount notification)
        int generation;                            // Increment each time the mount table is changed
        bool (*getBlockDiskActivity)(void *); // Disk activity callback: _getProcfsBlockDiskActivity (old kernels), _getSysfsBlockDiskActivity (new kernels)
        bool (*getCifsDiskActivity)(void *);  // Disk activity callback: _getCifsDiskActivity if /proc/fs/cifs/Stats is present, otherwise _getDummyDiskActivity
} _statistics = {};


/* ----------------------------------------------------------------- Private */


static bool _getDiskUsage(void *_inf) {
        Info_T inf = _inf;
        struct statvfs usage;
        if (statvfs(inf->filesystem->object.mountpoint, &usage) != 0) {
                Log_error("Error getting usage statistics for filesystem '%s' -- %s\n", inf->filesystem->object.mountpoint, STRERROR);
                return false;
        }
        inf->filesystem->f_bsize = usage.f_frsize;
        inf->filesystem->f_blocks = usage.f_blocks;
        inf->filesystem->f_blocksfree = usage.f_bavail;
        inf->filesystem->f_blocksfreetotal = usage.f_bfree;
        inf->filesystem->f_files = usage.f_files;
        inf->filesystem->f_filesfree = usage.f_ffree;
        return true;
}


static bool _getDummyDiskActivity(__attribute__ ((unused)) void *_inf) {
        return true;
}


static bool _getCifsDiskActivity(void *_inf) {
        Info_T inf = _inf;
        FILE *f = fopen(CIFSSTAT, "r");
        if (! f) {
                Log_error("Cannot open %s\n", CIFSSTAT);
                return false;
        }
        unsigned long long now = Time_milli();
        char line[PATH_MAX];
        bool found = false;
        while (fgets(line, sizeof(line), f)) {
                if (! found) {
                        int index;
                        char name[4096];
                        if (sscanf(line, "%d) %4095s", &index, name) == 2 && Str_isEqual(name, inf->filesystem->object.key)) {
                                found = true;
                        }
                } else if (found) {
                        char label1[256];
                        char label2[256];
                        unsigned long long operations;
                        unsigned long long bytes;
                        if (sscanf(line, "%255[^:]: %llu %255[^:]: %llu", label1, &operations, label2, &bytes) == 4) {
                                if (Str_isEqual(label1, "Reads") && Str_isEqual(label2, "Bytes")) {
                                        Statistics_update(&(inf->filesystem->read.bytes), now, bytes);
                                        Statistics_update(&(inf->filesystem->read.operations), now, operations);
                                } else if (Str_isEqual(label1, "Writes") && Str_isEqual(label2, "Bytes")) {
                                        Statistics_update(&(inf->filesystem->write.bytes), now, bytes);
                                        Statistics_update(&(inf->filesystem->write.operations), now, operations);
                                        break;
                                }
                        }
                }
        }
        fclose(f);
        return true;
}


static bool _getNfsDiskActivity(void *_inf) {
        Info_T inf = _inf;
        FILE *f = fopen(NFSSTAT, "r");
        if (! f) {
                Log_error("Cannot open %s\n", NFSSTAT);
                return false;
        }
        unsigned long long now = Time_milli();
        char line[PATH_MAX];
        char pattern[2 * PATH_MAX];
        bool found = false;
        snprintf(pattern, sizeof(pattern), "device %s ", inf->filesystem->object.device);
        while (fgets(line, sizeof(line), f)) {
                if (! found && Str_startsWith(line, pattern)) {
                        found = true;
                } else if (found) {
                        char name[256];
                        unsigned long long operations;
                        unsigned long long bytesSent;
                        unsigned long long bytesReceived;
                        unsigned long long time;
                        if (sscanf(line, " %255[^:]: %llu %*u %*u %llu %llu %*u %*u %llu", name, &operations, &bytesSent, &bytesReceived, &time) == 5) {
                                if (Str_isEqual(name, "READ")) {
                                        Statistics_update(&(inf->filesystem->time.read), now, time / 1000.); // us -> ms
                                        Statistics_update(&(inf->filesystem->read.bytes), now, bytesReceived);
                                        Statistics_update(&(inf->filesystem->read.operations), now, operations);
                                } else if (Str_isEqual(name, "WRITE")) {
                                        Statistics_update(&(inf->filesystem->time.write), now, time / 1000.); // us -> ms
                                        Statistics_update(&(inf->filesystem->write.bytes), now, bytesSent);
                                        Statistics_update(&(inf->filesystem->write.operations), now, operations);
                                        break;
                                }
                        }
                }
        }
        fclose(f);
        return true;
}


static bool _getZfsDiskActivity(void *_inf) {
        Info_T inf = _inf;
        char path[2 * PATH_MAX];
        snprintf(path, sizeof(path), "/proc/spl/kstat/zfs/%s/io", inf->filesystem->object.key);
        FILE *f = fopen(path, "r");
        if (f) {
                char line[STRLEN];
                unsigned long long now = Time_milli();
                unsigned long long waitTime = 0ULL, runTime = 0ULL;
                unsigned long long readOperations = 0ULL, readBytes = 0ULL;
                unsigned long long writeOperations = 0ULL, writeBytes = 0ULL;
                while (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "%llu %llu %llu %llu %llu %*u %*u %llu", &readBytes, &writeBytes, &readOperations, &writeOperations, &waitTime, &runTime) == 6) {
                                Statistics_update(&(inf->filesystem->read.bytes), now, readBytes);
                                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                                Statistics_update(&(inf->filesystem->write.bytes), now, writeBytes);
                                Statistics_update(&(inf->filesystem->write.operations), now, writeOperations);
                                Statistics_update(&(inf->filesystem->time.wait), now, (double)waitTime / 1000000.); // ns -> ms
                                Statistics_update(&(inf->filesystem->time.run), now, (double)runTime / 1000000.); // ns -> ms
                                break;
                        }
                }
                fclose(f);
                return true;
        }
        Log_error("filesystem statistic error: cannot read %s -- %s\n", path, STRERROR);
        return false;
}


static bool _getVxfsDiskActivity(void *_inf) {
        Info_T inf = _inf;

        // Get the major and minor node number to find the statistic data.
        struct stat statbuf;
        unsigned int st_major, st_minor;
        unsigned int major = 0, minor = 0;

        if (stat(inf->filesystem->object.device, &statbuf) < 0) {
                return false;
        }
        st_major = major(statbuf.st_rdev);
        st_minor = minor(statbuf.st_rdev);

        // Try to find the statistic data in the sysfs first.
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/stat", st_major, st_minor);
        FILE *f = fopen(path, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL, readTime = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL, writeTime = 0ULL;
                if (fscanf(f, "%llu %*u %llu %llu %llu %*u %llu %llu %*u %*u %*u", &readOperations, &readSectors, &readTime, &writeOperations, &writeSectors, &writeTime) != 6) {
                        Log_error("filesystem statistic error: cannot parse %s -- %s\n", path, STRERROR);
                        fclose(f);
                        return false;
                }
                Statistics_update(&(inf->filesystem->time.read), now, readTime);
                Statistics_update(&(inf->filesystem->read.bytes), now, readSectors * 512);
                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                Statistics_update(&(inf->filesystem->time.write), now, writeTime);
                Statistics_update(&(inf->filesystem->write.bytes), now, writeSectors * 512);
                Statistics_update(&(inf->filesystem->write.operations), now, writeOperations);
                fclose(f);
                return true;
        }
        DEBUG("filesystem statistic error: cannot read %s -- %s\n", path, STRERROR);

        // Use the procfs file for backup purpose only.
        // It should not used as main data collector, it support kernels >= 2.6.25 format only, too.
        f = fopen(DISKSTAT, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL, readTime = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL, writeTime = 0ULL;
                char line[PATH_MAX];
                while (fgets(line, sizeof(line), f)) {
                        char name[256] = {};

                        // Traverse the /proc/diskstats to have the statistics.
                        // The kernels >= 2.6.25 format with 11 fields is supported only.
                        if (fscanf(f, "%u %u %255s %llu %*u %llu %llu %llu %*u %llu %llu %*u %*u %*u", &major, &minor, name, &readOperations, &readSectors, &readTime, &writeOperations, &writeSectors, &writeTime) == 9 && major == st_major && minor == st_minor) {
                                Statistics_update(&(inf->filesystem->time.read), now, readTime);
                                Statistics_update(&(inf->filesystem->read.bytes), now, readSectors * 512);
                                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                                Statistics_update(&(inf->filesystem->time.write), now, writeTime);
                                Statistics_update(&(inf->filesystem->write.bytes), now, writeSectors * 512);
                                Statistics_update(&(inf->filesystem->write.operations), now, writeOperations);
                                fclose(f);
                                return true;
                        }
                }
                fclose(f);
                DEBUG("filesystem statistic error: cannot find device number %u %u for %s\n", st_major, st_minor, inf->filesystem->object.device);
        } else {
                DEBUG("filesystem statistic error: cannot read %s -- %s\n", DISKSTAT, STRERROR);
        }
        // Always true to get the disk usage, at least.
        return true;
}


static bool _getSysfsBlockDiskActivity(void *_inf) {
        Info_T inf = _inf;
        char path[2 * PATH_MAX];
        snprintf(path, sizeof(path), "/sys/class/block/%s/stat", inf->filesystem->object.key);
        FILE *f = fopen(path, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL, readTime = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL, writeTime = 0ULL;
                if (fscanf(f, "%llu %*u %llu %llu %llu %*u %llu %llu %*u %*u %*u", &readOperations, &readSectors, &readTime, &writeOperations, &writeSectors, &writeTime) != 6) {
                        fclose(f);
                        Log_error("filesystem statistic error: cannot parse %s -- %s\n", path, STRERROR);
                        return false;
                }
                Statistics_update(&(inf->filesystem->time.read), now, readTime);
                Statistics_update(&(inf->filesystem->read.bytes), now, readSectors * 512);
                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                Statistics_update(&(inf->filesystem->time.write), now, writeTime);
                Statistics_update(&(inf->filesystem->write.bytes), now, writeSectors * 512);
                Statistics_update(&(inf->filesystem->write.operations), now, writeOperations);
                fclose(f);
                return true;
        }
        Log_error("filesystem statistic error: cannot read %s -- %s\n", path, STRERROR);
        return false;
}


static bool _getProcfsBlockDiskActivity(void *_inf) {
        Info_T inf = _inf;
        FILE *f = fopen(DISKSTAT, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL;
                char line[PATH_MAX];
                while (fgets(line, sizeof(line), f)) {
                        char name[256] = {};
                        // Fallback for kernels < 2.6.25: the /proc/diskstats used to have just 4 statistics, the file is present on >= 2.6.25 too and has 11 fields (same format as /sys/class/block/<NAME>/stat), but we use sysfs for it
                        // as we read the given partition directly instead of traversing the whole filesystems list. In this function we expect the old 4-statistics format - if it should be ever used as main data collector, it needs to
                        // be modified to support >= 2.6.25 format too.
                        if (fscanf(f, " %*d %*d %255s %llu %llu %llu %llu", name, &readOperations, &readSectors, &writeOperations, &writeSectors) == 5 && Str_isEqual(name, inf->filesystem->object.key)) {
                                Statistics_update(&(inf->filesystem->read.bytes), now, readSectors * 512);
                                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                                Statistics_update(&(inf->filesystem->write.bytes), now, writeSectors * 512);
                                Statistics_update(&(inf->filesystem->write.operations), now, writeOperations);
                                break;
                        }
                }
                fclose(f);
                return true;
        }
        Log_error("filesystem statistic error: cannot read %s -- %s\n", DISKSTAT, STRERROR);
        return false;
}


static bool _compareMountpoint(const char *mountpoint, struct mntent *mnt) {
        return IS(mountpoint, mnt->mnt_dir);
}


static bool _compareDevice(const char *device, struct mntent *mnt) {
        char target[PATH_MAX] = {};
        // The device listed in /etc/mtab can be a device mapper symlink (e.g. /dev/mapper/centos-root -> /dev/dm-1) ... lookup the device as is first (support for NFS/CIFS/SSHFS/etc.) and fallback to realpath if it didn't match
        return (Str_isEqual(device, mnt->mnt_fsname) || (realpath(mnt->mnt_fsname, target) && Str_isEqual(device, target)));
}


static bool _setDevice(Info_T inf, const char *path, bool (*compare)(const char *path, struct mntent *mnt)) {
        FILE *f = setmntent(MOUNTS, "r");
        if (! f) {
                Log_error("Cannot open %s\n", MOUNTS);
                return false;
        }
        inf->filesystem->object.generation = _statistics.generation;
        bool mounted = false;
        struct mntent *mnt;
        char flags[STRLEN];
        while ((mnt = getmntent(f))) {
                // Scan all entries for overlay mounts (common for rootfs)
                if (compare(path, mnt)) {
                        snprintf(inf->filesystem->object.device, sizeof(inf->filesystem->object.device), "%s", mnt->mnt_fsname);
                        snprintf(inf->filesystem->object.mountpoint, sizeof(inf->filesystem->object.mountpoint), "%s", mnt->mnt_dir);
                        snprintf(inf->filesystem->object.type, sizeof(inf->filesystem->object.type), "%s", mnt->mnt_type);
                        snprintf(flags, sizeof(flags), "%s", mnt->mnt_opts);
                        inf->filesystem->object.getDiskUsage = _getDiskUsage; // The disk usage method is common for all filesystem types
                        inf->filesystem->object.getDiskActivity = _getDummyDiskActivity; // Set to dummy IO statistics method by default (can be overridden bellow if statistics method is available for this filesystem)
                        if (Str_startsWith(mnt->mnt_type, "nfs")) {
                                // NFS
                                inf->filesystem->object.getDiskActivity = _getNfsDiskActivity;
                        } else if (IS(mnt->mnt_type, "cifs")) {
                                // CIFS
                                inf->filesystem->object.getDiskActivity = _statistics.getCifsDiskActivity;
                                // Need Windows style name - replace '/' with '\' so we can lookup the filesystem activity in /proc/fs/cifs/Stats
                                snprintf(inf->filesystem->object.key, sizeof(inf->filesystem->object.key), "%s", inf->filesystem->object.device);
                                Str_replaceChar(inf->filesystem->object.key, '/', '\\');
                        } else if (IS(mnt->mnt_type, "zfs")) {
                                // ZFS
                                inf->filesystem->object.getDiskActivity = _getZfsDiskActivity;
                                // Need base zpool name for /proc/spl/kstat/zfs/<NAME>/io lookup:
                                snprintf(inf->filesystem->object.key, sizeof(inf->filesystem->object.key), "%s", inf->filesystem->object.device);
                                Str_replaceChar(inf->filesystem->object.key, '/', 0);
                        } else if (IS(mnt->mnt_type, "vxfs")) {
                                // VXFS, Veritas FS
                                inf->filesystem->object.getDiskActivity = _getVxfsDiskActivity;
                                // Use device major and minor number lookup in sysfs or procfs.
                                snprintf(inf->filesystem->object.key, sizeof(inf->filesystem->object.key), "%s", inf->filesystem->object.device);
                        } else {
                                if (realpath(mnt->mnt_fsname, inf->filesystem->object.key)) {
                                        // Need base name for /sys/class/block/<NAME>/stat or /proc/diskstats lookup:
                                        snprintf(inf->filesystem->object.key, sizeof(inf->filesystem->object.key), "%s", File_basename(inf->filesystem->object.key));
                                        // Test if block device statistics are available for the given filesystem
                                        if (_statistics.getBlockDiskActivity(inf)) {
                                                // Block device
                                                inf->filesystem->object.getDiskActivity = _statistics.getBlockDiskActivity;
                                        }
                                }
                        }
                        mounted = true;
                }
        }
        endmntent(f);
        inf->filesystem->object.mounted = mounted;
        if (! mounted) {
                Log_error("Lookup for '%s' filesystem failed  -- not found in %s\n", path, MOUNTS);
        } else {
                // Evaluate filesystem flags for the last matching mount (overlay mounts for the same filesystem may have different mount flags)
                if (! IS(flags, inf->filesystem->flags)) {
                        if (*(inf->filesystem->flags)) {
                                inf->filesystem->flagsChanged = true;
                        }
                        snprintf(inf->filesystem->flags, sizeof(inf->filesystem->flags), "%s", flags);
                }
        }
        return mounted;
}


static bool _getDevice(Info_T inf, const char *path, bool (*compare)(const char *path, struct mntent *mnt)) {
        // Mount/unmount notification: open the /proc/self/mounts file if we're in daemon mode and keep it open until monit
        // stops, so we can poll for mount table changes
        // FIXME: when libev is added register the mount table handler in libev and stop polling here
        if (_statistics.fd == -1 && (Run.flags & Run_Daemon) && ! (Run.flags & Run_Once)) {
                _statistics.fd = open(MOUNTS, O_RDONLY);
        }
        if (_statistics.fd != -1) {
                struct pollfd mountNotify = {.fd = _statistics.fd, .events = POLLPRI, .revents = 0};
                if (poll(&mountNotify, 1, 0) != -1) {
                        if (mountNotify.revents & POLLERR) {
                                DEBUG("Mount table change detected\n");
                                _statistics.generation++;
                        }
                } else {
                        Log_error("Mount table polling failed -- %s\n", STRERROR);
                }
        }
        if (inf->filesystem->object.generation != _statistics.generation || _statistics.fd == -1) {
                DEBUG("Reloading mount information for filesystem '%s'\n", path);
                _setDevice(inf, path, compare);
        }
        if (inf->filesystem->object.mounted) {
                return (inf->filesystem->object.getDiskUsage(inf) && inf->filesystem->object.getDiskActivity(inf));
        }
        return false;
}


/* --------------------------------------- Static constructor and destructor */


static void __attribute__ ((constructor)) _constructor(void) {
        struct stat sb;
        _statistics.fd = -1;
        _statistics.generation++; // First generation
        _statistics.getBlockDiskActivity = stat("/sys/class/block", &sb) == 0 ? _getSysfsBlockDiskActivity : _getProcfsBlockDiskActivity;
        _statistics.getCifsDiskActivity = stat(CIFSSTAT, &sb) == 0 ? _getCifsDiskActivity : _getDummyDiskActivity;
}


static void __attribute__ ((destructor)) _destructor(void) {
        if (_statistics.fd > -1) {
                  close(_statistics.fd);
        }
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

