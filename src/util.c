/* util.c - Genereal utility functions.
 * Copyright (C) 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010  Free Software Foundation, Inc.
 * Copyright (C) 2014, 2015 g10 Code GmbH
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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

#include "util.h"
#include "logging.h"

/* The error source number for Payproc.  */
gpg_err_source_t default_errsource;


/* A severe error was encountered.  Stop the process as soon as
   possible but first give other connections a chance to
   terminate.  */
void
severe_error (void)
{
  /* FIXME: stop only this thread and wait for other threads.  */
  exit (4);
}


static void
out_of_core(void)
{
  fputs ("\nfatal: out of memory\n", stderr);
  exit (2);
}


void *
xmalloc( size_t n )
{
  void *p = malloc( n );
  if (!p)
    out_of_core ();
  return p;
}


void *
xrealloc (void *a, size_t n)
{
  void *p = realloc (a, n);
  if (!p)
    out_of_core();
  return p;
}


void *
xcalloc (size_t n, size_t m)
{
  void *p = calloc( n, m );
  if (!p)
    out_of_core ();
  return p;
}


char *
xstrdup (const char *string)
{
  void *p = xmalloc (strlen(string)+1);
  strcpy (p, string);
  return p;
}



static char *
do_strconcat (const char *s1, va_list arg_ptr)
{
  const char *argv[48];
  size_t argc;
  size_t needed;
  char *buffer, *p;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        {
          gpg_err_set_errno (EINVAL);
          return NULL;
        }
      argc++;
    }
  needed++;
  buffer = xtrymalloc (needed);
  if (buffer)
    {
      for (p = buffer, argc=0; argv[argc]; argc++)
        p = stpcpy (p, argv[argc]);
    }
  return buffer;
}


/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *
strconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = xtrystrdup ("");
  else
    {
      va_start (arg_ptr, s1);
      result = do_strconcat (s1, arg_ptr);
      va_end (arg_ptr);
    }
  return result;
}


/* Upcase all ASCII characters in S.  */
char *
ascii_strupr (char *s)
{
  char *p = s;

  for (p=s; *p; p++ )
    if (!(*p & 0x80) && *p >= 'a' && *p <= 'z')
      *p &= ~0x20;

  return s;
}


/* Lowercase all ASCII characters in S.  */
char *
ascii_strlwr (char *s)
{
  char *p = s;

  for (p=s; *p; p++ )
    if (isascii (*p) && *p >= 'A' && *p <= 'Z')
      *p |= 0x20;

  return s;
}



/*
 * Check whether STRING starts with KEYWORD.  The keyword is
 * delimited by end of string, a space or a tab.  Returns NULL if not
 * found or a pointer into STRING to the next non-space character
 * after the KEYWORD (which may be end of string).
 */
char *
has_leading_keyword (const char *string, const char *keyword)
{
  size_t n = strlen (keyword);

  if (!strncmp (string, keyword, n)
      && (!string[n] || string[n] == ' ' || string[n] == '\t'))
    {
      string += n;
      while (*string == ' ' || *string == '\t')
        string++;
      return (char*)string;
    }
  return NULL;
}


/* Find string SUB in (BUFFER,BUFLEN).  */
const char *
memstr (const void *buffer, size_t buflen, const char *sub)
{
  const char *buf = buffer;
  const char *t = buf;
  const char *s = sub;
  size_t n = buflen;

  for (; n; t++, n--)
    {
      if (*t == *s)
        {
          for (buf = t++, buflen = n--, s++; n && *t == *s; t++, s++, n--)
            ;
          if (!*s)
            return buf;
          t = buf;
          s = sub ;
          n = buflen;
	}
    }
  return NULL;
}


/* Find string SUB in (BUFFER,BUFLEN).
 * Comparison is case-insensitive.  */
const char *
memistr (const void *buffer, size_t buflen, const char *sub)
{
  const unsigned char *buf = buffer;
  const unsigned char *t = (const unsigned char *)buffer;
  const unsigned char *s = (const unsigned char *)sub;
  size_t n = buflen;

  for ( ; n ; t++, n-- )
    {
      if ( toupper (*t) == toupper (*s) )
        {
          for ( buf=t++, buflen = n--, s++;
                n && toupper (*t) == toupper (*s); t++, s++, n-- )
            ;
          if (!*s)
            return (const char*)buf;
          t = buf;
          s = (const unsigned char *)sub ;
          n = buflen;
	}
    }
  return NULL;
}


int
memicmp (const char *a, const char *b, size_t n)
{
  for ( ; n; n--, a++, b++ )
    if (*a != *b && (toupper (*(const unsigned char*)a)
                     != toupper(*(const unsigned char*)b)))
      return *(const unsigned char *)a - *(const unsigned char*)b;
  return 0;
}


/*
 * Remove leading and trailing white space from STR.  Return STR.
 */
char *
trim_spaces (char *str)
{
  char *string, *p, *mark;

  string = str;
  /* Find first non space character.  */
  for( p=string; *p && isspace (*(unsigned char*)p) ; p++ )
    ;
  /* Move characters. */
  for (mark = NULL; (*string = *p); string++, p++ )
    {
      if (isspace (*(unsigned char*)p))
        {
          if (!mark)
            mark = string;
        }
      else
        mark = NULL;
    }
  if (mark)
    *mark = '\0' ;  /* Remove trailing spaces. */

  return str;
}


/* Tokenize STRING using the set of delimiters in DELIM.  Leading
 * spaces and tabs are removed from all tokens.  The caller must xfree
 * the result.
 *
 * Returns: A malloced and NULL delimited array with the tokens.  On
 *          memory error NULL is returned and ERRNO is set.
 */
char **
strtokenize (const char *string, const char *delim)
{
  const char *s;
  size_t fields;
  size_t bytes, n;
  char *buffer;
  char *p, *px, *pend;
  char **result;

  /* Count the number of fields.  */
  for (fields = 1, s = strpbrk (string, delim); s; s = strpbrk (s + 1, delim))
    fields++;
  fields++; /* Add one for the terminating NULL.  */

  /* Allocate an array for all fields, a terminating NULL, and space
     for a copy of the string.  */
  bytes = fields * sizeof *result;
  if (bytes / sizeof *result != fields)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  n = strlen (string) + 1;
  bytes += n;
  if (bytes < n)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  result = xtrymalloc (bytes);
  if (!result)
    return NULL;
  buffer = (char*)(result + fields);

  /* Copy and parse the string.  */
  strcpy (buffer, string);
  for (n = 0, p = buffer; (pend = strpbrk (p, delim)); p = pend + 1)
    {
      *pend = 0;
      while (spacep (p))
        p++;
      for (px = pend - 1; px >= p && spacep (px); px--)
        *px = 0;
      result[n++] = p;
    }
  while (spacep (p))
    p++;
  for (px = p + strlen (p) - 1; px >= p && spacep (px); px--)
    *px = 0;
  result[n++] = p;
  result[n] = NULL;

  assert ((char*)(result + n + 1) == buffer);

  return result;
}



keyvalue_t
keyvalue_find (keyvalue_t list, const char *key)
{
  keyvalue_t kv;

  for (kv = list; kv; kv = kv->next)
    if (!strcmp (kv->name, key))
      return kv;
  return NULL;
}

static keyvalue_t
keyvalue_create (const char *key, const char *value)
{
  keyvalue_t kv;

  /* Insert a new data item. */
  kv = xtrymalloc (sizeof *kv + strlen (key));
  if (!kv)
    return NULL;
  kv->next = NULL;
  strcpy (kv->name, key);
  kv->value = xtrystrdup (value);
  if (!kv->value)
    {
      xfree (kv);
      return NULL;
    }
  return kv;
}


/* Append the string VALUE to the current value of KV.  */
gpg_error_t
keyvalue_append_with_nl (keyvalue_t kv, const char *value)
{
  char *p;

  p = strconcat (kv->value, "\n", value, NULL);
  if (!p)
    return gpg_err_code_from_syserror ();
  xfree (kv->value);
  kv->value = p;
  return 0;
}


/* Remove all newlines from the value of KV.  This is done in place
   and works always.  */
void
keyvalue_remove_nl (keyvalue_t kv)
{
  char *s, *d;

  if (!kv || !kv->value)
    return;
  for (s = d = kv->value; *s; s++)
    if (*s != '\n')
      *d++ = *s;
  *d = 0;
}


gpg_error_t
keyvalue_put (keyvalue_t *list, const char *key, const char *value)
{
  keyvalue_t kv;
  char *buf;

  if (!key || !*key)
    return gpg_error (GPG_ERR_INV_VALUE);

  kv = keyvalue_find (*list, key);
  if (kv) /* Update.  */
    {
      if (value)
        {
          buf = xtrystrdup (value);
          if (!buf)
            return gpg_error_from_syserror ();
        }
      else
        buf = NULL;
      xfree (kv->value);
      kv->value = buf;
    }
  else if (value) /* Insert.  */
    {
      kv = keyvalue_create (key, value);
      if (!kv)
        return gpg_error_from_syserror ();
      kv->next = *list;
      *list = kv;
    }
  return 0;
}


/* This is the same as keyvalue_put but KEY is modified to include
   an index.  For example when using a value of 7 for IDX we get

     "Desc"       -> "Desc[7]"
     "Meta[Name]" -> "Meta[Name.7]"

   If IDX is -1 the function is identical to keyvalue_put.
 */
gpg_error_t
keyvalue_put_idx (keyvalue_t *list, const char *key, int idx, const char *value)
{
  char name[65];
  size_t n;

  if (idx < 0)
    return keyvalue_put (list, key, value);

  n = strlen (key);
  if (n > 2 && key[n-1] == ']')
    snprintf (name, sizeof name, "%.*s.%d]", (int)n-1, key, idx);
  else
    snprintf (name, sizeof name, "%s[%d]", key, idx);

  if (strlen (name) >= sizeof name - 1)
    return gpg_error (GPG_ERR_INV_LENGTH);

  return keyvalue_put (list, name, value);
}


gpg_error_t
keyvalue_del (keyvalue_t list, const char *key)
{
  /* LIST won't change due to the del operation.  */
  return keyvalue_put (&list, key, NULL);
}


gpg_error_t
keyvalue_putf (keyvalue_t *list, const char *key, const char *format, ...)
{
  gpg_error_t err;
  va_list arg_ptr;
  char *value;

  if (!key || !*key)
    return gpg_error (GPG_ERR_INV_VALUE);

  va_start (arg_ptr, format);
  value = gpgrt_vbsprintf (format, arg_ptr);
  va_end (arg_ptr);
  if (!value)
    return gpg_error_from_syserror ();

  err = keyvalue_put (list, key, value);
  es_free (value);
  return err;
}


/* Store STRING as "Meta" field at LIST.  */
gpg_error_t
keyvalue_put_meta (keyvalue_t *list, const char *string)
{
  gpg_error_t err;
  char *buffer;
  char key[64];
  char *next, *p;
  int i;

  buffer = xtrystrdup (string);
  if (!buffer)
    return gpg_error_from_syserror ();

  next = buffer;
  do
    {
      strcpy (key, "Meta[");
      for (i=5, p = next; *p != '='; i++, p++)
        {
          if (!*p || strchr ("%:&\n\r", *p) || i >= sizeof key - 3)
            {
              xfree (buffer);
              return gpg_error (GPG_ERR_INV_VALUE);  /* No or invalid name.  */
            }
          else
            key[i] = *p;
        }
      if (i==5)
        {
          xfree (buffer);
          return gpg_error (GPG_ERR_INV_VALUE);  /* Zero length name.  */
        }
      key[i++] = ']';
      key[i] = 0;
      p++;

      next = strchr (p, '&');
      if (next)
        *next++ = 0;

      p[percent_unescape_inplace (p, 0)] = 0;
      err = keyvalue_put (list, key, p);
      if (err)
        {
          xfree (buffer);
          return err;
        }
    }
  while (next && *next);

  xfree (buffer);
  return 0;
}


void
keyvalue_release (keyvalue_t kv)
{
  while (kv)
    {
      keyvalue_t nxt = kv->next;
      xfree (kv->value);
      xfree (kv);
      kv = nxt;
    }
}


const char *
keyvalue_get (keyvalue_t list, const char *key)
{
  keyvalue_t kv;

  for (kv = list; kv; kv = kv->next)
    if (!strcmp (kv->name, key))
      return kv->value;
  return NULL;
}


/* Same as keyvalue_get but return the value as a modifiable string
   and the value in LIST to NULL.  The caller must xfree the
   result.  */
char *
keyvalue_snatch (keyvalue_t list, const char *key)
{
  keyvalue_t kv;

  for (kv = list; kv; kv = kv->next)
    if (!strcmp (kv->name, key))
      {
        char *p = kv->value;
        kv->value = NULL;
        return p;
      }
  return NULL;
}


const char *
keyvalue_get_string (keyvalue_t list, const char *key)
{
  const char *s = keyvalue_get (list, key);
  return s? s: "";
}


int
keyvalue_get_int (keyvalue_t list, const char *key)
{
  const char *s = keyvalue_get (list, key);
  if (!s)
    return 0;
  return atoi (s);
}


unsigned int
keyvalue_get_uint (keyvalue_t list, const char *key)
{
  const char *s = keyvalue_get (list, key);
  if (!s)
    return 0;
  return strtoul (s, NULL, 10);
}



/* Parse the www-form-urlencoded DATA into a new dictionary and store
 * that dictionary at R_DICT.  On error store NULL at R_DICT and
 * return an error code.  */
gpg_error_t
parse_www_form_urlencoded (keyvalue_t *r_dict, const char *data)
{
  gpg_error_t err;
  char *string, *endp, *name, *value;
  size_t n;
  char *buffer = NULL;
  keyvalue_t dict = NULL;

  *r_dict = NULL;

  string = buffer = xtrystrdup (data);
  if (!string)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  do
    {
      endp = strchr (string, '&');
      if (endp)
        *endp = 0;

      name = string;
      value = strchr (name, '=');
      if (value)
        *value++ = 0;

      name[(n=percent_plus_unescape_inplace (name, 0))] = 0;
      if (!n || strlen (name) != n)
        {
          err = gpg_error (GPG_ERR_INV_VALUE); /* Nul in name or empty.  */
          goto leave;
        }

      if (value)
        {
          value[(n=percent_plus_unescape_inplace (value, 0))] = 0;
          if (strlen (value) != n)
            {
              err = gpg_error (GPG_ERR_INV_VALUE); /* Nul in value.  */
              goto leave;
            }
        }

      err = keyvalue_put (&dict, name, value? value:"");
      if (err)
        goto leave;

      if (endp)
        string = endp + 1;
    }
  while (endp);

  *r_dict = dict;
  dict = NULL;
  err = 0;

 leave:
  keyvalue_release (dict);
  xfree (buffer);
  return err;
}



/* Conversion table for base64_encode.  */
static char const bintoasc[64] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M',
  'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
  'a','b','c','d','e','f','g','h','i','j','k','l','m',
  'n','o','p','q','r','s','t','u','v','w','x','y','z',
  '0','1','2','3','4','5','6','7','8','9','+','/'
};


/* Encode (DATA,DATALEN) in Base64 format and return a malloced
 * string.  Returns NULL and sets ERRNO on error.  */
char *
base64_encode (const void *data, size_t datalen)
{
  char *buffer, *p;
  const unsigned char *s = data;
  size_t n = datalen;

  buffer = p = xtrymalloc ((n+2)/3*4 + 1);
  if (!buffer)
    return NULL;

  for (; n >= 3 ; n -= 3, s += 3)
    {
      *p++ = bintoasc[ ((s[0] >> 2)   & 077) ];
      *p++ = bintoasc[ ((((s[0] << 4) & 060) | ((s[1] >> 4) & 017)) & 077) ];
      *p++ = bintoasc[ ((((s[1] << 2) & 074) | ((s[2] >> 6) & 003)) & 077) ];
      *p++ = bintoasc[ (s[2] & 077) ];
    }
  if (n == 2)
    {
      *p++ = bintoasc[ ((s[0]   >> 2) & 077) ];
      *p++ = bintoasc[ ((((s[0] << 4) & 060) | ((s[1] >> 4) & 017)) & 077) ];
      *p++ = bintoasc[ ((s[1]   << 2) & 074) ];
      *p++ = '=';
    }
  else if (n == 1)
    {
      *p++ = bintoasc[ ((s[0] >> 2) & 077) ];
      *p++ = bintoasc[ ((s[0] << 4) & 060) ];
      *p++ = '=';
      *p++ = '=';
    }
  *p = 0;

  return buffer;
}


/* Decode plain Base64 encoded data in STRING and return it in at as a
 * malloced buffer at (DATA,DATALEN).  On error set them to (NULL,0)
 * and return an error code.  An extra Nul is always added to a
 * returned buffer. */
gpg_error_t
base64_decode (const char *string, void **r_data, size_t *r_datalen)
{
  gpg_error_t err;
  gpgrt_b64state_t state;
  char *buffer;
  size_t len;

  *r_data = NULL;
  *r_datalen = 0;

  buffer = xtrystrdup (string);
  if (!buffer)
    return gpg_error_from_syserror ();

  state = gpgrt_b64dec_start (NULL);
  if (!state)
    {
      err = gpg_error_from_syserror ();
      xfree (buffer);
      return err;
    }

  err = gpgrt_b64dec_proc (state, buffer, strlen (buffer), &len);
  if (err)
    {
      gpgrt_b64dec_finish (state);
      xfree (buffer);
      return err;
    }

  err = gpgrt_b64dec_finish (state);
  if (err)
    {
      xfree (buffer);
      return err;
    }
  buffer[len] = 0; /* We know that there is enough space for this.  */

  *r_data = buffer;
  *r_datalen = len;
  return 0;
}



/* Mapping table for zb32.  */
static char const zb32asc[32] = {'y','b','n','d','r','f','g','8',
                                 'e','j','k','m','c','p','q','x',
                                 'o','t','1','u','w','i','s','z',
                                 'a','3','4','5','h','7','6','9' };

/* If C is a valid ZB32 character return its index (0..31).  If it is
   not valid return -1.  */
int
zb32_index (int c)
{
  const char *p;

  p = memchr (zb32asc, c, 32);
  if (p)
    return p - zb32asc;
  if (c >= 'A' && c <= 'Z')
    {
      p = memchr (zb32asc, c - 'A' + 'a', 32);
      if (p)
        return p - zb32asc;
    }
  return -1;
}


/* Zooko's base32 variant. See RFC-6189 and
   http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
   Caller must xfree the returned string.  Returns NULL and sets ERRNO
   on error.  To avoid integer overflow DATALEN is limited to 2^16
   bytes.  Note, that DATABITS is measured in bits!.  */
char *
zb32_encode (const void *data, unsigned int databits)
{
  const unsigned char *s;
  char *output, *d;
  size_t datalen;

  datalen = (databits + 7) / 8;
  if (datalen > (1 << 16))
    {
      errno = EINVAL;
      return NULL;
    }

  d = output = xtrymalloc (8 * (datalen / 5)
                           + 2 * (datalen % 5)
                           - ((datalen%5)>2)
                           + 1);
  if (!output)
    return NULL;

  /* I use straightforward code.  The compiler should be able to do a
     better job on optimization than me and it is easier to read.  */
  for (s = data; datalen >= 5; s += 5, datalen -= 5)
    {
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1) | (s[3] >> 7) ];
      *d++ = zb32asc[((s[3] & 127) >> 2)               ];
      *d++ = zb32asc[((s[3] &   3) << 3) | (s[4] >> 5) ];
      *d++ = zb32asc[((s[4] &  31)     )               ];
    }

  switch (datalen)
    {
    case 4:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1) | (s[3] >> 7) ];
      *d++ = zb32asc[((s[3] & 127) >> 2)               ];
      *d++ = zb32asc[((s[3] &   3) << 3)               ];
      break;
    case 3:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4) | (s[2] >> 4) ];
      *d++ = zb32asc[((s[2] &  15) << 1)               ];
      break;
    case 2:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2) | (s[1] >> 6) ];
      *d++ = zb32asc[((s[1] &  63) >> 1)               ];
      *d++ = zb32asc[((s[1] &   1) << 4)               ];
      break;
    case 1:
      *d++ = zb32asc[((s[0]      ) >> 3)               ];
      *d++ = zb32asc[((s[0] &   7) << 2)               ];
      break;
    default:
      break;
    }
  *d = 0;

  /* Need to strip some bytes if not a multiple of 40.  */
  output[(databits + 5 - 1) / 5] = 0;
  return output;
}



/* Get the current time and put it into TIMESTAMP, which must be a
   buffer of at least TIMESTAMP_SIZE bytes.  */
char *
get_current_time (char *timestamp)
{
  time_t atime = time (NULL);
  struct tm *tp;

  if (atime == (time_t)(-1))
    {
      log_error ("time() failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }

#ifdef HAVE_GMTIME_R
  {
    struct tm tmbuf;

    tp = gmtime_r (&atime, &tmbuf);
  }
#else
  tp = gmtime (&atime);
#endif

  snprintf (timestamp, TIMESTAMP_SIZE, "%04d%02d%02dT%02d%02d%02d",
            1900 + tp->tm_year, tp->tm_mon+1, tp->tm_mday,
            tp->tm_hour, tp->tm_min, tp->tm_sec);
  return timestamp;
}



/* Check the amount given in STRING and convert it to the smallest
   currency unit.  DECDIGITS gives the number of allowed post decimal
   positions.  Return 0 on error or the converted amount.  */
unsigned int
convert_amount (const char *string, int decdigits)
{
  const char *s;
  int ndots = 0;
  int nfrac = 0;
  unsigned int value = 0;
  unsigned int v;

  if (*string == '+')
    string++; /* Skip an optional leading plus sign.  */
  for (s = string; *s; s++)
    {
      if (*s == '.')
        {
          if (!decdigits)
            return 0; /* Post decimal digits are not allowed.  */
          if (++ndots > 1)
            return 0; /* Too many decimal points.  */
        }
      else if (!strchr ("0123456789", *s))
        return 0;
      else if (ndots && ++nfrac > decdigits)
        return 0; /* Too many post decimal digits.  */
      else
        {
          v = 10*value + (*s - '0');
          if (v < value)
            return 0; /* Overflow.  */
          value = v;
        }
    }

  for (; nfrac < decdigits; nfrac++)
    {
      v = 10*value;
      if (v < value)
        return 0; /* Overflow.  */
      value = v;
    }

  return value;
}


/* Return a string with the amount computed from CENTS.  DECDIGITS
   gives the number of post decimal positions in CENTS.  Return NULL
   on error.  es_free must be used to release the return value.  */
char *
reconvert_amount (int cents, int decdigits)
{
  unsigned int tens;
  int i;

  if (decdigits <= 0)
    return es_bsprintf ("%d", cents);
  else
    {
      for (tens=1, i=0; i < decdigits; i++)
        tens *= 10;
      return es_bsprintf ("%d.%0*d", cents / tens, decdigits, cents % tens);
    }
}



/* Write buffer BUF of length LEN to stream FP.  Escape all characters
   in a way that the stream can be used for a colon delimited line
   format including structured URL like fields.  */
static void
write_escaped_buf (const void *buf, size_t len, estream_t fp)
{
  const unsigned char *s;

  for (s = buf; len; s++, len--)
    {
      if (!strchr (":&\n\r", *s))
        es_putc (*s, fp);
      else
        es_fprintf (fp, "%%%02X", *s);
    }
}


/* Write STRING to stream FP.  Escape all characters in a way that the
   stream can be used for a colon delimited line format including
   structured URL like fields.  */
void
write_escaped (const char *string, estream_t fp)
{
  write_escaped_buf (string, strlen (string), fp);
}


/* Iterate over all keys named "Meta[FOO]" for all FOO and print the
   meta data field.  */
void
write_meta_field (keyvalue_t dict, estream_t fp)
{
  keyvalue_t kv;
  const char *s, *name;
  int any = 0;

  for (kv=dict; kv; kv = kv->next)
    {
      if (!strncmp (kv->name, "Meta[", 5) && kv->value && *kv->value)
        {
          name = kv->name + 5;
          for (s = name; *s; s++)
            {
              if (*s == ']')
                break;
              else if (strchr ("=& \t", *s))
                break;
            }
          if (*s != ']' || s == name || s[1])
            continue; /* Not a valid key.  */
          if (!any)
            any = 1;
          else
            es_putc ('&', fp);
          write_escaped_buf (name, s - name, fp);
          es_putc ('=', fp);
          write_escaped_buf (kv->value, strlen (kv->value), fp);
        }
    }
}


/* Create a structured string from the "Meta" field.  On error NULL is
   return.  The returned string must be released with es_free.  */
char *
meta_field_to_string (keyvalue_t dict)
{
  estream_t fp;
  void *buffer;
  int writefailed;
  keyvalue_t kv;

  for (kv=dict; kv; kv = kv->next)
    if (!strncmp (kv->name, "Meta[", 5) && kv->value && *kv->value)
      break;
  if (!kv)
    return NULL;/* No Meta data field.  */

  fp = es_fopenmem (0, "w+,samethread");
  if (!fp)
    {
      log_error ("error creating new memory stream for the Meta field: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      return NULL;
    }

  write_meta_field (dict, fp);

  /* Write an extra Nul so that we can snatched the memory as C-string. */
  if ((writefailed = es_fwrite ("", 1, 1, fp) != 1)
      || es_fclose_snatch (fp, &buffer, NULL))
    {
      log_error ("error closing memory stream for the Meta field: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      if (writefailed)
        es_fclose (fp);
      return NULL;
    }

  return buffer;
}
