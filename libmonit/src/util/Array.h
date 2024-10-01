/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
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

#ifndef ARRAY_INCLUDED
#define ARRAY_INCLUDED


/**
 * A simple <b>Sparse Array</b> keyed on int with values of any type.
 * The array supports integer keys in the full range (including negative
 * values) and stores values of any pointer type. Note that iterating
 * from i = 0 to Array_length does not guarantee a continuous set of
 * values. Use Array_map to visit all values or Array_get to look up
 * a specific value by key. The 'hint' parameter in Array_new is used
 * to estimate the initial array size for efficient storage based on
 * the expected number of elements.
 *
 * Performance: Average time complexity for insertion, lookup, and
 * deletion is generally O(1), assuming a well-distributed key space
 * and a reasonable load factor.
 *
 * This class is reentrant but not thread-safe
 *
 * @author http://www.tildeslash.com/
 * @see https://mmonit.com
 * @file
 */


#define T Array_T
typedef struct T *T;


/**
 * Create a new Sparse Array object
 * @param hint An estimate of the number of entries the Array is expected to
 * contain; accurate values of <code>hint</code> may improve performance, but
 * any nonnegative value is acceptable.
 * @return A new Sparse Array object
 * @exception MemoryException if allocation failed
 */
T Array_new(int hint);


/**
 * Destroy a Sparse Array object and release allocated resources.
 * @param S A Sparse Array object reference
 */
void Array_free(T *S);


/**
 * Adds the key-value pair given by <code>key</code> and <code>value</code>
 * to Array. If the Array already holds <code>key</code>, <code>value</code>
 * overwrites the previous value, and returns the <i>previous</i> value.
 * Otherwise <code>key</code> and <code>value</code> are added to the
 * Array, which grows by one entry, and Array_put() returns NULL.
 * @param S A Sparse Array object
 * @param key An int value
 * @param value A value reference. It's the callers responsibility
 * to maintain memory management of the value.
 * @return The previous value for key or NULL if key is new
 * @exception MemoryException if allocation failed
 */
void *Array_put(T S, int key, void *value);


/**
 * Returns the value associated with <code>key</code>
 * @param S A Sparse Array object
 * @param key The key to lookup
 * @return The value associated with <code>key</code> or NULL if Array does
 * not hold <code>key</code>.
 */
void *Array_get(T S, int key);


/**
 * Removes the key-value pair from Array if <code>key</code> was found in Array.
 * The removed value is returned. If Array does not hold <code>key</code>, this
 * method has no effect and returns NULL.
 * @param S A Sparse Array object
 * @param key The key to lookup
 * @return The value associated with <code>key</code> or NULL if Array does
 * not hold <code>key</code>.
 */
void *Array_remove(T S, int key);


/**
 * Returns the number of key-value pairs in Array
 * @param S A Sparse Array object
 * @return The number of entries in the Array
 */
int Array_length(T S);


/**
 * Apply the visitor function, <code>apply</code> for each key-value pair in
 * Array. Clients can pass an application specific pointer, <code>ap</code>,
 * to Array_map() and this pointer is passed along to the <code>apply</code>
 * function on each call. It is a checked runtime error for <code>apply</code>
 * to change the Array.
 * @param S A Sparse Array object
 * @param apply The function to apply. Note that value is the address to the
 * value object
 * @param ap An application-specific pointer. If such a pointer is
 * not needed, just use NULL
 * @exception AssertException if <code>apply</code> changes the Array
 */
void Array_map(T S, void apply(int key, void **value, void *ap), void *ap);


/**
 * Search the Array for a particular value using a <code>predicate</code>
 * function and a needle. If the predicate function returns true for a
 * value, that value is returned. If no matching value is found, the
 * function returns NULL. The average time complexity is O(n), assuming
 * uniform key distribution.
 * @param S A Sparse Array object
 * @param predicate The predicate function used for comparison. It should
 * return true if a value in the array matches the needle, otherwise false.
 * @param needle A pointer to a search term used by the predicate function
 * to compare with a value in the array.
 * @return A pointer to the value in the Sparse Array that satisfies the
 * predicate, or NULL if no such value is found.
 * @exception AssertException if <code>predicate</code> changes the Array
 */
void *Array_find(T S, bool predicate(void *value, void *needle), void *needle);


#undef T
#endif
