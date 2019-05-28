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

// Partial vector implementation with potentially less memory overhead,
// useful when you need many small vectors.
// Template parameter I is the type used to index the vector.
// e.g., ivector<uint16_t, Foo> foovec;

#ifndef _IVECTOR_H
#define _IVECTOR_H 1

#include <cstddef>
#include <iostream>

template<typename I, typename T, typename Alloc = std::allocator<T> >
class ivector {
public:
    // types
    typedef T value_type;
    typedef typename Alloc::pointer                   pointer;
    typedef typename Alloc::const_pointer             const_pointer;
    typedef typename Alloc::reference                 reference;
    typedef typename Alloc::const_reference           const_reference;
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef T* iterator;
    typedef const T* const_iterator;
private:
    // Typical std::vector implementations use 3 pointers; this is more
    // compact if sizeof(I) < sizeof(T*), e.g. on a 64-bit platform with
    // I = uint32_t.
    I _size;
    I dynCapacity;
    // possible hole here if I is small or T's alignment is big
    T *dynStart;

    // When _size <= locCapacity(), we store the data directly in *this after
    // _size, and don't need to allocate _start.  (We can't use a union of
    // Local and Dynamic structs (before C++11), because T may have a
    // constructor.  Instead, we must calculate alignment and size manually.)
    struct Layout { I _size; T data; };
    T *locStart() const { return &((Layout*)this)->data; } // properly aligned
    size_type locCapacity() const
	// can't be static and use offsetof(), because T may be non-POD
	{ return ((char*)(this + 1) - (char*)locStart()) / sizeof(T); }

    void copy_contents_backward(T *first, T *last, T *result) {
	for (int i = last - first; i > 0; --i) {
	    Alloc().construct(result + i - 1, first[i-1]);
	    Alloc().destroy(first + i - 1);
	}
    }
    value_type *ptr(size_type i=0) const
	{ return (_size <= locCapacity() ? locStart() : dynStart) + i; }
    void grow(I amount = 1) {
	I newsize = _size + amount;
	if (newsize <= locCapacity()) {
	    // do nothing
	} else if (_size <= locCapacity()) {
	    T *newstart = Alloc().allocate(newsize);
	    copy_contents_backward(ptr(), ptr(_size), newstart);
	    dynStart = newstart;
	    dynCapacity = newsize;
	} else if (newsize > dynCapacity) {
	    I newcap = int(dynCapacity * 1.3) + 1;
	    if (newcap < newsize) newcap = newsize;
	    reserve(newcap);
	}
	_size = newsize;
    }
    void destroy_contents() {
	T *start = ptr();
	for (T *p = start; p < start + _size; ++p) { Alloc().destroy(p); }
    }
public:
    // constructors
    ivector() : _size(0) {}
    explicit ivector(I n, const T & val = T()) {
	T *start;
	if (n > locCapacity()) {
	    _size = n;
	    dynCapacity = n;
	    dynStart = Alloc().allocate(n);
	    start = dynStart;
	} else {
	    _size = n;
	    start = locStart();
	}
	for (T *p = start; p < start + n; ++p) Alloc().construct(p, val);
    }
    // destructor
    ~ivector() {
	destroy_contents();
	if (_size > locCapacity())
	    Alloc().deallocate(dynStart, dynCapacity);
    }
    // methods
    iterator begin() { return ptr(); }
    const_iterator begin() const { return ptr(); }
    iterator end() { return ptr(_size); }
    const_iterator end() const { return ptr(_size); }
    size_type size() const { return _size; }
    size_type max_size() const { return 0xFFFF; }
    size_type capacity() const
	{ return _size <= locCapacity() ? locCapacity() : dynCapacity; }
    size_t memory() const {
	return sizeof(*this) +
	    (_size <= locCapacity() ? 0 : dynCapacity * sizeof(T));
    }
    bool empty() const { return _size == 0; }
    reference operator[](size_type i) { return *ptr(i); }
    const_reference operator[](size_type i) const { return *ptr(i); }
    void reserve(size_t n) {
	if (n > capacity()) {
	    T *newstart = Alloc().allocate(n);
	    copy_contents_backward(ptr(), ptr(_size), newstart);
	    if (_size > locCapacity())
		Alloc().deallocate(dynStart, dynCapacity);
	    dynStart = newstart;
	    dynCapacity = n;
	}
    }
    void push_back(const T& x) { grow(); *ptr(_size-1) = x; }
    void swap(ivector &x) {
	// this may have holes if I is small, so we use memcpy
	ivector tmp;
	memcpy(&tmp, x, sizeof(ivector));
	memcpy(&x, this, sizeof(ivector));
	memcpy(this, &tmp, sizeof(ivector));
    }
    iterator insert(iterator pos, const T &x) {
	size_type offset = pos - ptr();
	grow(); // may move _start
	copy_contents_backward(ptr(offset), ptr(_size - 1), ptr(offset + 1));
	Alloc().construct(ptr(offset), x);
	return ptr(offset);
    }
    void insert(iterator pos, iterator start, iterator stop) {
	I oldsize = _size;
	size_type offset = pos - ptr();
	grow(stop - start); // may move _start
	copy_contents_backward(ptr(offset), ptr(oldsize), ptr(offset + stop - start));
	copy_contents_backward(start, stop, ptr(offset));
    }
    //iterator erase(iterator pos) {
    //    Alloc().destroy(pos, 1);
    //    copy_contents(pos+1, ptr(_size), pos);
    //    --_size;
    //    return pos;
    //}
    void clear() { _size = 0; }
    void free(bool corrupt = false) {
	destroy_contents();
	if (_size > locCapacity()) {
	    Alloc().deallocate(dynStart, dynCapacity);
	}
	if (corrupt) {
	    _size = locCapacity() + 1; // so we'll try to dereference _start
	    dynCapacity = 0;
	    // invalid address, so dereferencing will crash the program
	    *(new(&dynStart)(char*)) = &static_cast<char*>(0)[-1];
	} else {
	    _size = 0;
	    dynCapacity = 0; dynStart = 0;
	}
    }
};

#endif /* _IVECTOR_H */
