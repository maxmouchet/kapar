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

/*
 * File reading interface that handles gzipped as well as regular files.
 */

#ifndef INFILE_H
#define INFILE_H

//#include <stdio.h>
#include <stdexcept>
#ifdef HAVE_LIBZ
# include <zlib.h>
#endif
#ifdef HAVE_PTHREAD
# include <pthread.h>
#endif

class InFile {
    bool isPipe;
    const char *pipeName;
    char *tmp;
    FILE *file;
    long _linenum;
#ifdef HAVE_LIBZ
    gzFile gzfile;
#ifdef HAVE_PTHREAD
    int pipes[2];
    pthread_t pthread;
    static void *run_gzreader(void *arg);
#endif
    void check_gzerror();
#endif
    struct Mismatch : public std::exception {
	Mismatch() : std::exception() { }
	const char *what() const throw() { return "InFile header/library mismatch"; }
    };
public:
    static bool fork;
    const char * const name;
    const char * basename;
    explicit InFile(const char *filename, size_t classize = sizeof(InFile));
    // You should always call .close() explicitly and catch its exceptions.
    // The dtor closes implicitly if needed, but does not throw exceptions.
    ~InFile() {
	try { close(); } catch (...) { /* throwing from dtor is unsafe */ }
    }
    char *gets(char *buf, unsigned len);
    size_t read(void *buf, size_t size, size_t nmemb);
    long linenum() const { return _linenum; }
    int fd() throw();
    void close();
    class Error : public std::runtime_error {
	char buf[2048];
      public:
	Error(const InFile &in, const char *fmt, ...) throw();
	Error(const InFile &in, const std::exception &e) throw();
	const char *what() const throw() { return buf; }
    };
    bool nameEndsWith(const char *ending) const;
};

#endif // INFILE_H
