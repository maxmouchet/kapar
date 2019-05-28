/* 
 * Copyright (C) 2011-2018 The Regents of the University of California.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// $Id: MemoryInfo.h,v 1.7 2012/01/03 20:49:25 kkeys Exp $
// Track memory and CPU usage

#ifndef MEMORYINFO_H
#define MEMORYINFO_H

#include <sys/time.h>

class MemoryInfo {
#if NO_DEBUG_MEMORY
    inline void print(const char *label) const { /* do nothing */ }
#else
    uint32_t getTimeMillis() {
	struct timeval tv;
	gettimeofday(&tv, 0);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }
    bool use_proc;
    bool use_bsd_ps;
    char ps_cmd[32];
    int64_t initMem, prevMem;
    int64_t initTime, prevTime;
    long tickspersec;
public:
    MemoryInfo();
    void print(const char *label);
#endif
};

#endif // MEMORYINFO_H
