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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#ifdef HAVE_DISKARBITRATION_DISKARBITRATION_H
#include <DiskArbitration/DiskArbitration.h>
#endif

#ifdef HAVE_IOKIT_STORAGE_IOBLOCKSTORAGEDRIVER_H
#include <IOKit/storage/IOBlockStorageDriver.h>
#endif

#include "monit.h"
#include "device.h"

// libmonit
#include "system/Time.h"


/* ----------------------------------------------------------------- Private */


static bool _getDiskUsage(void *_inf) {
        Info_T inf = _inf;
        struct statfs usage;
        if (statfs(inf->filesystem->object.mountpoint, &usage) != 0) {
                Log_error("Error getting usage statistics for filesystem '%s' -- %s\n", inf->filesystem->object.mountpoint, System_lastError());
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


static bool _getDummyDiskActivity(__attribute__ ((unused)) void *_inf) {
        return true;
}


static bool _getBlockDiskActivity(void *_inf) {
        int rv = false;
        Info_T inf = _inf;
        DASessionRef session = DASessionCreate(NULL);
        if (session) {
                CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)inf->filesystem->object.mountpoint, strlen(inf->filesystem->object.mountpoint), true);
                DADiskRef disk = DADiskCreateFromVolumePath(NULL, session, url);
                if (disk) {
                        DADiskRef wholeDisk = DADiskCopyWholeDisk(disk);
                        if (wholeDisk) {
                                io_service_t ioMedia = DADiskCopyIOMedia(wholeDisk);
                                if (ioMedia) {
                                        CFTypeRef statistics = IORegistryEntrySearchCFProperty(ioMedia, kIOServicePlane, CFSTR(kIOBlockStorageDriverStatisticsKey), kCFAllocatorDefault, kIORegistryIterateRecursively | kIORegistryIterateParents);
                                        if (statistics) {
                                                rv = true;
                                                UInt64 value = 0;
                                                unsigned long long now = Time_milli();
                                                // Total read bytes
                                                CFNumberRef number = CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->read.bytes), now, value);
                                                }
                                                // Total read operations
                                                number = CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsReadsKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->read.operations), now, value);
                                                }
                                                // Total write bytes
                                                number = (CFNumberRef)CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->write.bytes), now, value);
                                                }
                                                // Total write operations
                                                number = CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsWritesKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->write.operations), now, value);
                                                }
                                                // Total read time
                                                number = CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsTotalReadTimeKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->time.read), now, value / 1048576.); // ns -> ms
                                                }
                                                // Total write time
                                                number = CFDictionaryGetValue(statistics, CFSTR(kIOBlockStorageDriverStatisticsTotalWriteTimeKey));
                                                if (number) {
                                                        CFNumberGetValue(number, kCFNumberSInt64Type, &value);
                                                        Statistics_update(&(inf->filesystem->time.write), now, value / 1048576.); // ns -> ms
                                                }
                                                //FIXME: add disk error statistics test: can use kIOBlockStorageDriverStatisticsWriteErrorsKey + kIOBlockStorageDriverStatisticsReadErrorsKey
                                                CFRelease(statistics);
                                        }
                                        IOObjectRelease(ioMedia);
                                }
                                CFRelease(wholeDisk);
                        }
                        CFRelease(disk);
                }
                CFRelease(url);
                CFRelease(session);
        }
        return rv;
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
#ifdef MNT_REMOVABLE
                {MNT_REMOVABLE, "removable"},
#endif
                {MNT_SYNCHRONOUS, "synchronous"},
                {MNT_NOEXEC, "noexec"},
                {MNT_NOSUID, "nosuid"},
                {MNT_NODEV, "nodev"},
                {MNT_UNION, "union"},
                {MNT_ASYNC, "async"},
                {MNT_DOVOLFS, "dovolfs"},
#ifdef MNT_CPROTECT
                {MNT_CPROTECT, "content protection"},
#endif
                {MNT_EXPORTED, "exported"},
                {MNT_QUARANTINE, "quarantined"},
                {MNT_LOCAL, "local"},
                {MNT_QUOTA, "quota"},
                {MNT_ROOTFS, "rootfs"},
                {MNT_DONTBROWSE, "nobrowse"},
                {MNT_IGNORE_OWNERSHIP, "noowners"},
                {MNT_AUTOMOUNTED, "automounted"},
                {MNT_JOURNALED, "journaled"},
                {MNT_NOUSERXATTR, "nouserxattr"},
                {MNT_DEFWRITE, "defer writes"},
                {MNT_MULTILABEL, "multilabel"},
                {MNT_NOATIME, "noatime"},
#ifdef MNT_SNAPSHOT
                {MNT_SNAPSHOT, "snapshot"},
#endif
#ifdef MNT_STRICTATIME
                {MNT_STRICTATIME, "strictatime"}
#endif
        };
        Util_swapFilesystemFlags(&(inf->filesystem->flags));
        for (size_t i = 0, count = 0; i < sizeof(t) / sizeof(t[0]); i++) {
                if (flags & t[i].flag) {
                        snprintf(inf->filesystem->flags.current + strlen(inf->filesystem->flags.current), sizeof(inf->filesystem->flags.value[0]) - strlen(inf->filesystem->flags.current) - 1, "%s%s", count++ ? ", " : "", t[i].description);
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
                                        if (IS(mntItem->f_fstypename, "hfs") || IS(mntItem->f_fstypename, "apfs")) {
                                                inf->filesystem->object.getDiskActivity = _getBlockDiskActivity;
                                        } else {
                                                inf->filesystem->object.getDiskActivity = _getDummyDiskActivity;
                                        }
                                        inf->filesystem->object.flags = mntItem->f_flags & MNT_VISFLAGMASK;
                                        _filesystemFlagsToString(inf, inf->filesystem->object.flags);
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
        Log_error("Lookup for '%s' filesystem failed\n", path);
        inf->filesystem->object.mounted = false;
        return false;
}


static bool _getDevice(Info_T inf, const char *path, bool (*compare)(const char *path, struct statfs *mnt)) {
        //FIXME: cache mount information (register for mount/unmount notification)
        if (_setDevice(inf, path, compare)) {
                return (inf->filesystem->object.getDiskUsage(inf) && inf->filesystem->object.getDiskActivity(inf));
        }
        return false;
}


/* ------------------------------------------------------------------ Public */


bool Filesystem_getByMountpoint(Info_T inf, const char *path) {
        assert(inf);
        assert(path);
        return _getDevice(inf, path, _compareMountpoint);
}


bool Filesystem_getByDevice(Info_T inf, const char *path) {
        assert(inf);
        assert(path);
        return _getDevice(inf, path, _compareDevice);
}

