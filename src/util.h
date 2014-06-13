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

#undef JNLIB_GCC_HAVE_PUSH_PRAGMA
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define JNLIB_GCC_M_FUNCTION 1
# define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
# if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4 )
#   define JNLIB_GCC_HAVE_PUSH_PRAGMA 1
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

/* Macros to replace ctype ones to avoid locale problems. */
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
/* Note this isn't identical to a C locale isspace() without \f and
   \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define xtoi_4(p)   ((xtoi_2(p) * 256) + xtoi_2((p)+2))


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
const char *memstr (const void *buffer, size_t buflen, const char *sub);
const char *memistr (const void *buffer, size_t buflen, const char *sub);
int memicmp (const char *a, const char *b, size_t n);
char *trim_spaces (char *str);


/* Object to store a key value pair.  */
struct keyvalue_s
{
  struct keyvalue_s *next;
  char *value;    /* The value of the item (malloced).  */
  char name[1];   /* The name of the item (canonicalized). */
};

typedef struct keyvalue_s *keyvalue_t;

gpg_error_t keyvalue_append_with_nl (keyvalue_t kv, const char *value);
void keyvalue_remove_nl (keyvalue_t kv);
gpg_error_t keyvalue_put (keyvalue_t *list,
                               const char *key, const char *value);
gpg_error_t keyvalue_del (keyvalue_t list, const char *key);
gpg_error_t keyvalue_putf (keyvalue_t *list, const char *key,
                           const char *format, ...) JNLIB_GCC_A_PRINTF (3,4);
void keyvalue_release (keyvalue_t kv);
keyvalue_t keyvalue_find (keyvalue_t list, const char *key);
const char *keyvalue_get (keyvalue_t list, const char *key);
char *keyvalue_snatch (keyvalue_t list, const char *key);
const char *keyvalue_get_string (keyvalue_t list, const char *key);
int         keyvalue_get_int (keyvalue_t list, const char *key);

gpg_error_t parse_www_form_urlencoded (keyvalue_t *r_dict, char *string);

int zb32_index (int c);
char *zb32_encode (const void *data, unsigned int databits);

/*-- percent.c --*/
char *percent_plus_escape (const char *string);
char *percent_plus_unescape (const char *string, int nulrepl);
char *percent_unescape (const char *string, int nulrepl);
size_t percent_plus_unescape_inplace (char *string, int nulrepl);
size_t percent_unescape_inplace (char *string, int nulrepl);


#endif /*UTIL_H*/
