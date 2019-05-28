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

// $Id: Pool.h,v 1.4 2011/09/28 19:07:01 kkeys Exp $

#ifndef POOL_H
#define POOL_H

// Allocator optimized for large numbers of same-sized objects with low memory
// overhead.
template<class T>
class Pool {
    static const int BLOCKSIZE = 1023;
    struct Block {
	Block *next; // next block in blocklist
	T data[BLOCKSIZE]; // tightly packed array of objects
    };
    void *freelist; // singly-linked list of freed objects
    Block *blocklist; // singly-linked list of blocks
public:
    Pool() : freelist(0), blocklist(0) {
	if (sizeof(T) < sizeof(void*))
	    throw std::runtime_error("type too small for Pool");
    }
    void *alloc(size_t n) {
	if (n != sizeof(T))
	    return ::operator new(n);
	void *p = freelist;
	if (p) {
	    freelist = *(char**)p;
	} else {
	    Block *block = static_cast<Block*>(::operator new(sizeof(Block)));
	    // put all but first item on freelist
	    for (int i = 1; i < BLOCKSIZE - 1; ++i) {
		// using placement-new on lhs avoids compiler warning
		*(new(&block->data[i])(char*)) = reinterpret_cast<char*>(&block->data[i+1]);
	    }
	    // terminate freelist
	    // using placement-new on lhs avoids compiler warning
	    *(new(&block->data[BLOCKSIZE-1])(char*)) = 0;
	    freelist = &block->data[1];
	    block->next = blocklist;
	    blocklist = block;
	    p = &block->data[0];
	}
	return p;
    }
    void free(void *p, size_t n) {
	if (!p) return;
	if (n != sizeof(T)) { ::operator delete(p); return; } // XXX n?
	// put item on freelist
	*(void**)p = freelist;
	freelist = p;
    }
    ~Pool() { }
    void freeall() {
	// quickly frees all blocks allocated by this pool
	while (blocklist) {
	    Block *dead = blocklist;
	    blocklist = blocklist->next;
	    delete dead;
	}
    }
};

#endif // POOL_H
