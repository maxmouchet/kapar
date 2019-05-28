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

// Track memory and CPU usage

#include "config.h"
static const char *cvsID UNUSED = "$Id: MemoryInfo.cc,v 1.7 2015/09/18 19:19:01 kkeys Exp $";

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

#include <errno.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdlib.h>
#include <cstdio>
#include <string.h>
#include <unistd.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "MemoryInfo.h"

using namespace std;

#if !NO_DEBUG_MEMORY
MemoryInfo::MemoryInfo() {
    FILE *f = fopen("/proc/self/stat", "r");
    if (f) {
	// linux
	use_proc = true;
	fclose(f);
	initMem = 0;
	initTime = 0;
	tickspersec = sysconf(_SC_CLK_TCK);
	prevMem = initMem;
	prevTime = initTime;
	return;
    }
    use_proc = false;
    initTime = getTimeMillis();
    sprintf(ps_cmd, "/bin/ps -ovsz -p%ld", long(getpid()));
    f = popen(ps_cmd, "r");
    if (f) {
	char buf[2048];
	if (fgets(buf, sizeof(buf), f)) {
	    if (strcmp(buf, "  VSZ\n") == 0) {
		use_bsd_ps = true;
	    }
	}
	pclose(f);
    }
    // TODO: implement with getrusage
    initMem = (char*)sbrk(0) - (char*)0;
    prevMem = initMem;
    prevTime = initTime;
}

void MemoryInfo::print(const char *label) {
    FILE *f = 0;
    int64_t nowMem;
    uint64_t nowTime;
    if (use_proc) {
	f = fopen("/proc/self/stat", "r");
	char buf[2048];
	if (!fgets(buf, sizeof(buf), f)) {
	    cerr << "# perf: error: " << strerror(errno) << endl;
	    goto err;
	}
	const char *p = strstr(buf, ") ");
	if (!p) {
	    cerr << "# perf: error: bad format" << endl;
	    goto err;
	}
	p += 2;
	int i = 3;
	uint64_t vsize, utime, stime;
	while (i < 14) { while (*p && !isspace(*p++)) {/*nop*/} i++; }
	sscanf(p, "%"SCNu64 " %"SCNu64, &utime, &stime);
	while (i < 23) { while (*p && !isspace(*p++)) {/*nop*/} i++; }
	sscanf(p, "%"SCNu64, &vsize);
	nowMem = vsize;
	nowTime = (utime + stime) * 1000 / tickspersec;
    } else if (use_bsd_ps) {
	f = popen(ps_cmd, "r");
	char buf[2048];
	for (int i = 0; i < 2; i++) {
	    if (!fgets(buf, sizeof(buf), f)) {
		cerr << "# perf: error: " << strerror(errno) << endl;
		goto err;
	    }
	}
	nowMem = strtoull(buf, 0, 10) * 1024;
	nowTime = getTimeMillis();
    } else {
	nowMem = (char*)sbrk(0) - (char*)0;
	nowTime = getTimeMillis();
    }
    cerr << "# perf: " << setw(18) << label << ": " <<
	setw(8) << (nowMem - prevMem) / 1024 << " / " << setw(8) << (nowMem - initMem) / 1024 << " kiB, " <<
	setw(9) << (nowTime - prevTime) << " / " << setw(9) << (nowTime - initTime) << " ms" << endl;
    prevMem = nowMem;
    prevTime = nowTime;
    err:
    if (use_proc) {
	fclose(f);
    } else if (use_bsd_ps) {
	pclose(f);
    }
}
#endif
