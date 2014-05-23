/* session.c - Session management
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
#include <unistd.h>
#include <time.h>
#include <npth.h>
#include <gcrypt.h>

#include "util.h"
#include "logging.h"
#include "estream.h"
#include "payprocd.h"
#include "session.h"

/* The default TTL for a session is 30 minutes.  Each access to
   session data re-triggers this TTL. */
#define DEFAULT_TTL 1800

/* To inhibit people from using payproc as a cheap storage provider we
   limit the entire lifetime of a session to 6 hours.  */
#define MAX_SESSION_LIFETIME (6*3600)

/* We put a limit on the number of active sessions.  2^16 seems to be
   a reasonable value.  A session object without data requires about
   64 byte and thus we need about 4MB to hold the session objects.
   Assuming 1k of data on average per session and additional 64MB is
   used for the data. */
#define MAX_SESSIONS   65536

/* We use 20 bytes for the session id.  Using the ZB32 encoder this
   results in a 32 byte ascii string.  To avoid decoding of the
   session string we store the ascii string .  */
#define SESSID_RAW_LENGTH 20
#define SESSID_LENGTH 32


/* The object holding the session data.  */
struct session_s
{
  session_t next;  /* The next item in the bucket.  */
  unsigned int ttl;/* The session expires after this number of seconds
                      without activity.  */
  time_t created;  /* The time the session was created.  */
  time_t accessed; /* The time the session was last used.  */

  keyvalue_t dict; /* The dictionary with the session's data.  */

  /* The session id as ZB32 encoded string. */
  char sessid[SESSID_LENGTH+1];
};


/* A mutex used to protect the global session variables.  */
static npth_mutex_t sessions_lock = NPTH_MUTEX_INITIALIZER;

/* We store pointers to the session objects in 1024 buckets, indexed
   by the first two ZB32 encoded characters of the session id.  This
   requires 8k of memory for fast indexing which is not too much.  */
static session_t sessions[32][32];

/* Total number of sessions in use.  This counter is used to quickly
   check whether we are allowed to create a new session.  */
static unsigned int sessions_in_use;

/* Because the session objects have a fixed size, it is easy to reuse
   them.  */
static session_t unused_sessions;




static gpg_error_t
lock_sessions (void)
{
  int res;

  res = npth_mutex_lock (&sessions_lock);
  if (res)
    {
      gpg_error_t err = gpg_error_from_errno (res);
      log_error ("failed to acquire sessions lock: %s\n", gpg_strerror (err));
      return err;
    }

  return 0;
}


static void
unlock_sessions (void)
{
  int res;

  res = npth_mutex_unlock (&sessions_lock);
  if (res)
    {
      gpg_error_t err = gpg_error_from_errno (res);
      log_error ("failed to release sessions lock: %s\n", gpg_strerror (err));
    }
}




static int
check_ttl (session_t sess, time_t now)
{
  if ((sess->ttl > 0 && sess->accessed + sess->ttl < now)
      || (sess->created + MAX_SESSION_LIFETIME < now))
    {
      log_debug ("session '%s' expired\n", sess->sessid);
      return 1;
    }
  return 0;
}


/* Housekeeping; i.e. time out sessions.  */
void
session_housekeeping (void)
{
  time_t now = time (NULL);
  session_t prev, sess;
  int a, b;

  if (lock_sessions ())
    return;

  for (a=0; a < 32; a++)
    for (b=0; b < 32; b++)
      {
      again:
        for (sess = sessions[a][b], prev = NULL; sess;
             prev = sess, sess = sess->next)
          {
            if (check_ttl (sess, now))
              {
                /* Remove the item from the hash table.  */
                if (prev)
                  prev->next = sess->next;
                else
                  sessions[a][b] = sess->next;
                sessions_in_use--;

                /* Remove the data.  */
                keyvalue_release (sess->dict);
                sess->dict = NULL;

                /* Shove the item into the attic.  */
                sess->next = unused_sessions;
                unused_sessions = sess;

                /* Scan this bucket again.  */
                goto again;
              }
          }
      }

  unlock_sessions ();
}




/* Create a new session.  If TTL > 0 use that as TTL for the session.
   DICT is an optional dictionary with the data to store in the
   session.  On return a malloced string with the session-id is stored
   at R_SESSID. */
gpg_error_t
session_create (int ttl, keyvalue_t dict, char **r_sessid)
{
  gpg_error_t err;
  session_t sess = NULL;
  int malloced = 0;
  char nonce[SESSID_RAW_LENGTH];
  keyvalue_t kv;
  char *p;
  int a, b;

  *r_sessid = NULL;

  /* Cap the TTL at the session lifetime.  */
  if (ttl > MAX_SESSION_LIFETIME)
    ttl = MAX_SESSION_LIFETIME;

  err = lock_sessions ();
  if (err)
    return err;

  if (unused_sessions)
    {
      sess = unused_sessions;
      unused_sessions = sess->next;
      sess->next = NULL;
    }
  else if (sessions_in_use < MAX_SESSIONS)
    {
      sess = xtrycalloc (1, sizeof *sess);
      if (!sess)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      malloced = 1;
    }
  else
    {
      err = gpg_error (GPG_ERR_LIMIT_REACHED);
      goto leave;
    }

  gcry_create_nonce (nonce, sizeof nonce);
  p = zb32_encode (nonce, 8*sizeof nonce);
  if (!p)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (p) != SESSID_LENGTH)
    BUG ();
  strcpy (sess->sessid, p);
  *r_sessid = p;

  sess->created = sess->accessed = time (NULL);
  sess->ttl = ttl > 0? ttl : DEFAULT_TTL;
  sess->dict = NULL;  /* Just to be safe.  */

  for (kv = dict; kv; kv = kv->next)
    if (*kv->name)
      {
        err = keyvalue_put (&sess->dict, kv->name,
                            (kv->value && *kv->value)? kv->value : NULL);
        if (err)
          goto leave;
      }

  /* Put the session into the hash table.  */
  a = zb32_index (sess->sessid[0]);
  b = zb32_index (sess->sessid[1]);
  if ( a < 0 || a > 31 || b < 0 || b > 32)
    BUG ();
  sess->next = sessions[a][b];
  sessions[a][b] = sess;
  sess = NULL;
  sessions_in_use++;

 leave:
  if (sess)
    {
      keyvalue_release (sess->dict);
      sess->dict = NULL;

      /* Push an unused session object back or release it.  */
      if (malloced)
        xfree (sess);
      else
        {
          sess->next = unused_sessions;
          unused_sessions = sess;
        }
    }
  if (err)
    {
      xfree (*r_sessid);
      *r_sessid = NULL;
    }
  unlock_sessions ();
  return err;
}


/* Internal version of session_destroy.  */
static gpg_error_t
session_do_destroy (const char *sessid, int with_lock)
{
  gpg_error_t err;
  session_t prev, sess;
  int a, b;

  if (strlen (sessid) != SESSID_LENGTH
      || (a = zb32_index (sessid[0])) < 0
      || (b = zb32_index (sessid[1])) < 0)
    {
      return gpg_error (GPG_ERR_INV_NAME);
    }

  if (with_lock)
    {
      err = lock_sessions ();
      if (err)
        return err;
    }

  for (sess = sessions[a][b], prev = NULL; sess; prev = sess, sess = sess->next)
    if (!strcmp (sess->sessid, sessid))
      break;
  if (!sess)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* Remove the item from the hash table.  */
  if (prev)
    prev->next = sess->next;
  else
    sessions[a][b] = sess->next;
  sessions_in_use--;

  /* Remove the data.  */
  keyvalue_release (sess->dict);
  sess->dict = NULL;

  /* Shove the item into the attic.  */
  sess->next = unused_sessions;
  unused_sessions = sess;

 leave:
  if (with_lock)
    unlock_sessions ();
  return err;
}


/* Destroy the session SESSID.  */
gpg_error_t
session_destroy (const char *sessid)
{
  return session_do_destroy (sessid, 1);
}



/* Update the data for session SESSID using the dictionary DICT.  If
   the value of a dictionary entry is the empty string, that entry is
   removed from the session. */
gpg_error_t
session_put (const char *sessid, keyvalue_t dict)
{
  gpg_error_t err;
  time_t now;
  session_t sess;
  keyvalue_t kv;
  int a, b;

  if (strlen (sessid) != SESSID_LENGTH
      || (a = zb32_index (sessid[0])) < 0
      || (b = zb32_index (sessid[1])) < 0)
    {
      return gpg_error (GPG_ERR_INV_NAME);
    }

  err = lock_sessions ();
  if (err)
    return err;

  for (sess = sessions[a][b]; sess; sess = sess->next)
    if (!strcmp (sess->sessid, sessid))
      break;
  if (!sess)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  now = time (NULL);
  if (check_ttl (sess, now))
    {
      session_do_destroy (sessid, 0);
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }
  sess->accessed = now;

  /* Note: This is not an atomic operation.  If the put fails the
     session dictionary may be only partly updated.  However, the only
     reason for a failure is a memory shortage which is anyway a
     deadend - at least for the session.  */
  for (kv = dict; kv; kv = kv->next)
    if (*kv->name)
      {
        err = keyvalue_put (&sess->dict, kv->name,
                            (kv->value && *kv->value)? kv->value : NULL);
        if (err)
          goto leave;
      }

 leave:
  unlock_sessions ();
  return err;
}



/* Update the dictionary at address DICTP with the data from session
   SESSID. */
gpg_error_t
session_get (const char *sessid, keyvalue_t *dictp)
{
  gpg_error_t err;
  time_t now;
  session_t sess;
  keyvalue_t kv;
  int a, b;

  if (strlen (sessid) != SESSID_LENGTH
      || (a = zb32_index (sessid[0])) < 0
      || (b = zb32_index (sessid[1])) < 0)
    {
      return gpg_error (GPG_ERR_INV_NAME);
    }

  err = lock_sessions ();
  if (err)
    return err;

  for (sess = sessions[a][b]; sess; sess = sess->next)
    if (!strcmp (sess->sessid, sessid))
      break;
  if (!sess)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  now = time (NULL);
  if (check_ttl (sess, now))
    {
      session_do_destroy (sessid, 0);
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }
  sess->accessed = now;

  for (kv = sess->dict; kv; kv = kv->next)
    if (*kv->name)
      {
        err = keyvalue_put (dictp, kv->name,
                            (kv->value && *kv->value)? kv->value : NULL);
        if (err)
          goto leave;
      }

 leave:
  unlock_sessions ();
  return err;
}
