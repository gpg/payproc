/* form.c - Form handling functions
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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "util.h"
#include "membuf.h"
#include "http.h"
#include "form.h"


/* Encode the data in FORM for use with POST.  */
gpg_error_t
encode_formdata (keyvalue_t form, char **r_encoded)
{
  gpg_error_t err;
  membuf_t mb;
  keyvalue_t kv;
  char *escaped;

  *r_encoded = NULL;

  init_membuf (&mb, 0);
  for (kv = form; kv; kv = kv->next)
    {
      if (kv != form)
        put_membuf_str (&mb, "&");
      escaped = http_escape_string (kv->name, NULL/*form-encoding*/);
      if (!escaped)
        {
          err = gpg_error_from_syserror ();
          xfree (get_membuf (&mb, NULL));
          return err;
        }
      put_membuf_str (&mb, escaped);
      xfree (escaped);
      put_membuf_str (&mb, "=");
      escaped = http_escape_string (kv->value, NULL/*form-encoding*/);
      if (!escaped)
        {
          err = gpg_error_from_syserror ();
          xfree (get_membuf (&mb, NULL));
          return err;
        }
      put_membuf_str (&mb, escaped);
      xfree (escaped);
    }

  put_membuf (&mb, "", 1);
  *r_encoded = get_membuf (&mb, NULL);
  if (!*r_encoded)
    return gpg_error_from_syserror ();
  return 0;
}
