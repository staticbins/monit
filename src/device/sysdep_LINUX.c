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

#ifdef HAVE_GLOB_H
#include <glob.h>
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
        bool (*getBlockDiskActivity)(void *); // Disk activity callback: _getProcfsBlockDiskActivity or _getSysfsBlockDiskActivity (if sysfs is mounted)
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


static bool _getZfsObjsetId(Info_T inf) {
        // Find all objset files in the /proc/spl/kstat/zfs/<zpool>/ directory
        char path[PATH_MAX] = {};
        snprintf(path, sizeof(path), "/proc/spl/kstat/zfs/%.256s/objset-0x[a-fA-F0-9]*", inf->filesystem->object.key);

        glob_t globbuf;
        int rv = glob(path, 0, NULL, &globbuf);
        if (rv) {
                Log_error("system statistic error -- glob failed: %d (%s)\n", rv, STRERROR);
                return false;
        }

        // Scan objset list and find the matching dataset
        char datasetName[STRLEN] = {};
        for (size_t i = 0; i < globbuf.gl_pathc; i++) {
                FILE *f = fopen(globbuf.gl_pathv[i], "r");
                if (f) {
                        char line[STRLEN];
                        while (fgets(line, sizeof(line), f)) {
                                if (sscanf(line, "dataset_name %*d %255s", datasetName) == 1) {
                                        if (Str_isByteEqual(datasetName, inf->filesystem->object.device)) {
                                                // Cache the path to statistics, so we can fetch the data directly next time
                                                strncpy(inf->filesystem->object.module, globbuf.gl_pathv[i], sizeof(inf->filesystem->object.module) - 1);
                                                fclose(f);
                                                return true;
                                        } else {
                                                // The dataset name doesn't match, try next objset file
                                                break;
                                        }
                                }
                        }
                        fclose(f);
                }
        }
        return false;
}


static bool _updateZfsStatistics(Info_T inf) {
        FILE *f = fopen(inf->filesystem->object.module, "r");
        if (f) {
                char line[STRLEN];
                long long nread    = -1LL;
                long long reads    = -1LL;
                long long nwritten = -1LL;
                long long writes   = -1LL;
                while (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "nread %*d %lld", &nread) == 1)
                                continue;
                        else if (sscanf(line, "reads %*d %lld", &reads) == 1)
                                continue;
                        else if (sscanf(line, "nwritten %*d %lld", &nwritten) == 1)
                                continue;
                        else if (sscanf(line, "writes %*d %lld", &writes) == 1)
                                continue;
                }
                fclose(f);
                if (nread >= 0 && reads >= 0 && nwritten >= 0 && writes >= 0) {
                        unsigned long long now = Time_milli();
                        Statistics_update(&(inf->filesystem->read.bytes), now, nread);
                        Statistics_update(&(inf->filesystem->read.operations), now, reads);
                        Statistics_update(&(inf->filesystem->write.bytes), now, nwritten);
                        Statistics_update(&(inf->filesystem->write.operations), now, writes);
                        return true;
                } else {
                        Log_error("filesystem statistic error: cannot parse ZFS statistics from %s\n", inf->filesystem->object.module);
                }
        } else {
                Log_error("filesystem statistic error: cannot read ZFS statistics from %s -- %s\n", inf->filesystem->object.module, STRERROR);
        }
        return false;
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
        } else {
                // OpenZFS 2.x

                // We cache the objset ID in the object.module ... if not set, scan the system information
                if (STR_UNDEF(inf->filesystem->object.module)) {
                        if (! _getZfsObjsetId(inf))
                                return false;
                }
                return _updateZfsStatistics(inf);
        }
}


// See https://www.kernel.org/doc/Documentation/block/stat.txt
static bool _getSysfsBlockDiskActivity(void *_inf) {
        Info_T inf = _inf;
        char path[2 * PATH_MAX];
        snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/stat", inf->filesystem->object.number.major, inf->filesystem->object.number.minor);
        FILE *f = fopen(path, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL, readTime = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL, writeTime = 0ULL;
                if (fscanf(f, "%llu %*u %llu %llu %llu %*u %llu %llu", &readOperations, &readSectors, &readTime, &writeOperations, &writeSectors, &writeTime) != 6) {
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


// See https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
static bool _getProcfsBlockDiskActivity(void *_inf) {
        Info_T inf = _inf;
        FILE *f = fopen(DISKSTAT, "r");
        if (f) {
                unsigned long long now = Time_milli();
                unsigned long long readOperations = 0ULL, readSectors = 0ULL, readTime = 0ULL;
                unsigned long long writeOperations = 0ULL, writeSectors = 0ULL, writeTime = 0ULL;
                char line[PATH_MAX];
                while (fgets(line, sizeof(line), f)) {
                        int rv;
                        int major;
                        int minor;
                        char name[256] = {};
                        // Note: There are 17 fields in kernel 5.5+, we may use them in the future
                        rv = fscanf(f, " %d %d %255s %llu %*u %llu %llu %llu %*u %llu %llu", &major, &minor, name, &readOperations, &readSectors, &readTime, &writeOperations, &writeSectors, &writeTime);
                        if (rv == 9 && major == inf->filesystem->object.number.major && minor == inf->filesystem->object.number.minor) {
                                Statistics_update(&(inf->filesystem->time.read), now, readTime);
                                Statistics_update(&(inf->filesystem->read.bytes), now, readSectors * 512);
                                Statistics_update(&(inf->filesystem->read.operations), now, readOperations);
                                Statistics_update(&(inf->filesystem->time.write), now, writeTime);
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


static bool _getDeviceNumbers(const char *device, int *major, int *minor) {
        struct stat sb;
        if (stat(device, &sb) != 0) {
                *major = *minor = -1;
                return false;
        }
        *major = major(sb.st_rdev);
        *minor = minor(sb.st_rdev);
        return true;
}


static bool _compareMountpoint(const char *mountpoint, struct mntent *mnt) {
        return IS(mountpoint, mnt->mnt_dir);
}


static bool _compareDevice(const char *device, struct mntent *mnt) {
        int mnt_major, mnt_minor;
        int device_major, device_minor;
        char target[PATH_MAX] = {};
        if (Str_isEqual(device, mnt->mnt_fsname)) {
                // lookup the device as is first (support for NFS/CIFS/SSHFS/etc.)
                DEBUG("device %s matches filesystem %s (mounted on %s)\n", device, mnt->mnt_fsname, mnt->mnt_dir);
                return true;
        } else if (realpath(mnt->mnt_fsname, target) && Str_isEqual(device, target)) {
                // The device listed in /etc/mtab can be a device mapper symlink (e.g. /dev/mapper/centos-root -> /dev/dm-1), i.e. try realpath
                DEBUG("device %s matches real path %s for filesystem %s (mounted on %s)\n", device, target, mnt->mnt_fsname, mnt->mnt_dir);
                return true;
        } else if (_getDeviceNumbers(device, &device_major, &device_minor) && _getDeviceNumbers(mnt->mnt_fsname, &mnt_major, &mnt_minor) && (mnt_major == device_major) && (mnt_minor == device_minor)) {
                // The same filesystem may have multiple independent device nodes with the same major+minor number (e.g. block devices /dev/root and /dev/xvda1 for the same filesystem) => if path didn't match, compare major+minor
                DEBUG("device %s with major=%d and minor=%d number matches filesystem %s (mounted on %s)\n", device, mnt_major, mnt_minor, mnt->mnt_fsname, mnt->mnt_dir);
                return true;
        }
        return false;
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
        char flags[STRLEN] = {};
        while ((mnt = getmntent(f))) {
                // Scan all entries for overlay mounts (common for rootfs)
                if (compare(path, mnt)) {
                        snprintf(inf->filesystem->object.device, sizeof(inf->filesystem->object.device), "%s", mnt->mnt_fsname);
                        snprintf(inf->filesystem->object.mountpoint, sizeof(inf->filesystem->object.mountpoint), "%s", mnt->mnt_dir);
                        snprintf(inf->filesystem->object.type, sizeof(inf->filesystem->object.type), "%s", mnt->mnt_type);
                        snprintf(flags, sizeof(flags), "%s", mnt->mnt_opts);
                        inf->filesystem->object.getDiskUsage = _getDiskUsage; // The disk usage method is common for all filesystem types
                        inf->filesystem->object.getDiskActivity = _getDummyDiskActivity; // Set to dummy IO statistics method by default (can be overridden bellow if statistics method is available for this filesystem)
                        // Get the major and minor device number
                        _getDeviceNumbers(inf->filesystem->object.device, &(inf->filesystem->object.number.major), &(inf->filesystem->object.number.minor));
                        // Set filesystem-dependent callbacks
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
                // Store the flags value at the end. The same filesystem may have overlay mounts (with different flags), we don't want to corrupt the flags in the monit status, until we find the (last) matching filesystem
                Util_swapFilesystemFlags(&(inf->filesystem->flags));
                snprintf(inf->filesystem->flags.current, sizeof(inf->filesystem->flags.value[0]), "%s", flags);
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
        } else {
                strncpy(inf->filesystem->flags.previous, inf->filesystem->flags.current, sizeof(inf->filesystem->flags.value[0]));
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

