/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 * Copyright (c) 1994,1995,1996,1997 by David R. Hanson.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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

#include "Config.h"

#include <stdlib.h>
#include <limits.h>

#include "Array.h"


/**
 * Implementation of the Sparse Array interface. Based on the "Table"
 * implementation from David Hanson's excellent CII library. Hanson's
 * implementation is a general Hash Table, while this implementation
 * is a Sparse Array based on a hash table core.
 *
 * @author https://tildeslash.com
 * @see https://mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define T Array_T
struct T {
        int size;
        int length;
        unsigned int timestamp;
        struct binding *freelist;
        struct binding {
                int key;
                void *value;
                struct binding *link;
        } **buckets;
};


/* ---------------------------------------------------------------- Public */


T Array_new(int hint) {
        assert(hint >=0);
        static int primes[] = {
                127, 127, 251, 509, 1021, 2053, 4093,
                8191, 16381, 32771, 65521, INT_MAX
        };
        int i;
        for (i = 1; primes[i] < hint; i++) ;
        T S = CALLOC(1, sizeof (*S) + primes[i - 1] * sizeof (S->buckets[0]));
        S->size = primes[i-1];
        S->buckets = (struct binding **)(S + 1);
        for (i = 0; i < S->size; i++)
                S->buckets[i] = NULL;
        S->length = 0;
        S->timestamp = 0;
        return S;
}


void Array_free(T *S) {
        assert(S && *S);
        struct binding *p, *q;
        if ((*S)->length > 0) {
                for (int i = 0; i < (*S)->size; i++) {
                        for (p = (*S)->buckets[i]; p; p = q) {
                                q = p->link;
                                FREE(p);
                        }
                }
        }
        for (p = (*S)->freelist; p; p = q) {
                q = p->link;
                FREE(p);
        }
        FREE(*S);
}


void *Array_put(T S, int key, void *value) {
        assert(S);
        void *prev = NULL;
        struct binding *p;
        int i = abs(key)%S->size;
        for (p = S->buckets[i]; p; p = p->link)
                if (p->key == key)
                        break;
        if (p == NULL) {
                if (S->freelist) {
                        p = S->freelist;
                        S->freelist = p->link;
                } else {
                        NEW(p);
                }
                p->key = key;
                p->link = S->buckets[i];
                S->buckets[i] = p;
                S->length++;
        } else
                prev = p->value;
        p->value = value;
        S->timestamp++;
        return prev;
}


void *Array_get(T S, int key) {
        assert(S);
        int i = abs(key)%S->size;
        for (struct binding *p = S->buckets[i]; p; p = p->link) {
            if (p->key == key) {
                return p->value;
            }
        }
        return NULL;
}


void *Array_remove(T S, int key) {
        assert(S);
        int i = abs(key)%S->size;
        for (struct binding **pp = &S->buckets[i]; *pp; pp = &(*pp)->link) {
                if ((*pp)->key == key) {
                        struct binding *p = *pp;
                        void *value = p->value;
                        *pp = p->link;

                        // Retain binding for reuse
                        p->link = S->freelist;
                        S->freelist = p;

                        S->length--;
                        S->timestamp++;
                        return value;
                }
        }
        return NULL;
}


int Array_length(T S) {
        assert(S);
        return S->length;
}


void Array_map(T S, void apply(int key, void **value, void *ap), void *ap) {
        assert(S);
        assert(apply);
        unsigned int stamp = S->timestamp;
        for (int i = 0; i < S->size; i++)
                for (struct binding *p = S->buckets[i]; p; p = p->link) {
                        apply(p->key, &p->value, ap);
                        assert(S->timestamp == stamp);
                }
}


void *Array_find(T S, bool predicate(void *value, void *needle), void *needle) {
        assert(S);
        assert(predicate);
        assert(needle);
        unsigned int stamp = S->timestamp;
        for (int i = 0; i < S->size; i++)
                for (struct binding *p = S->buckets[i]; p; p = p->link) {
                        if (predicate(p->value, needle))
                            return p->value;
                        assert(S->timestamp == stamp);
                }
        return NULL;
}
