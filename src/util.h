/* util.h - Utility definitions for payproc
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of Payproc.
 *
 * Payproc is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Payproc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UTIL_H
#define UTIL_H

#include <gpg-error.h>


#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif
#ifndef DIMof
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define JNLIB_GCC_M_FUNCTION 1
# define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
# if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4 )
#   define JNLIB_GCC_A_PRINTF( f, a ) \
                    __attribute__ ((format (__gnu_printf__,f,a)))
#   define JNLIB_GCC_A_NR_PRINTF( f, a ) \
		    __attribute__ ((noreturn, format (__gnu_printf__,f,a)))
# else
#   define JNLIB_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#   define JNLIB_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
# endif
#else
# define JNLIB_GCC_A_NR
# define JNLIB_GCC_A_PRINTF( f, a )
# define JNLIB_GCC_A_NR_PRINTF( f, a )
#endif

#if __GNUC__ >= 4
# define JNLIB_GCC_A_SENTINEL(a) __attribute__ ((sentinel(a)))
#else
# define JNLIB_GCC_A_SENTINEL(a)
#endif


#define xtrymalloc(a)    malloc ((a))
#define xtrycalloc(a,b)  calloc ((a),(b))
#define xtryrealloc(a,b) realloc ((a),(b))
#define xtrystrdup(a)    strdup ((a))
#define xfree(a)         free ((a))

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
              volatile char *_vptr=(volatile char *)(_ptr); \
              size_t _vlen=(_len); \
              while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
                  } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)


/* The default error source of the application.  This is different
   from GPG_ERR_SOURCE_DEFAULT in that it does not depend on the
   source file and thus is usable in code shared by applications.  */
extern gpg_err_source_t default_errsource;


/*-- util.c --*/
void *xmalloc (size_t n);
void *xrealloc (void *a, size_t n);
void *xcalloc (size_t n, size_t m);
char *xstrdup (const char *string);

/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *strconcat (const char *s1, ...) JNLIB_GCC_A_SENTINEL(0);


char *has_leading_keyword (const char *string, const char *keyword);


/* Object to store a key value pair.  */
struct keyvalue_s
{
  struct keyvalue_s *next;
  char *value;    /* The value of the item (malloced).  */
  char name[1];   /* The name of the item (canonicalized). */
};

typedef struct keyvalue_s *keyvalue_t;

keyvalue_t keyvalue_create (const char *key, const char *value);
gpg_error_t keyvalue_append_to_last (keyvalue_t kv, const char *value);
gpg_error_t keyvalue_put (keyvalue_t *list,
                               const char *key, const char *value);
gpg_error_t keyvalue_putf (keyvalue_t *list, const char *key,
                           const char *format, ...) JNLIB_GCC_A_PRINTF (3,4);
void keyvalue_release (keyvalue_t kv);
const char *keyvalue_get (keyvalue_t list, const char *key);
const char *keyvalue_get_string (keyvalue_t list, const char *key);



#endif /*UTIL_H*/
