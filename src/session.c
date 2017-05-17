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

/* The number of aliases we may store for one session.  */
#define MAX_ALIASES_PER_SESSION   3

/* We use 20 bytes for the session id.  Using the ZB32 encoder this
   results in a 32 byte ascii string.  To avoid decoding of the
   session string we store the ascii string .  */
#define SESSID_RAW_LENGTH 20
#define SESSID_LENGTH 32


struct session_alias_s;
typedef struct session_alias_s *session_alias_t;


/* The object holding the session data.  */
struct session_s
{
  session_t next;  /* The next item in the bucket.  */
  unsigned int ttl;/* The session expires after this number of seconds
                      without activity.  */
  time_t created;  /* The time the session was created.  */
  time_t accessed; /* The time the session was last used.  */

  keyvalue_t dict; /* The dictionary with the session's data.  */

  /* Back references to alias objects or NULL.  */
  session_alias_t aliases[MAX_ALIASES_PER_SESSION];

  /* The session id as ZB32 encoded string. */
  char sessid[SESSID_LENGTH+1];
};


/* The object holding an alias to a session object.  */
struct session_alias_s
{
  session_alias_t next;  /* The next item in the bucket.  */

  /* The reference to the session object.  */
  session_t sess;

  /* The session alias id as ZB32 encoded string. */
  char aliasid[SESSID_LENGTH+1];
};


/* A mutex used to protect the global session variables.  */
static npth_mutex_t sessions_lock = NPTH_MUTEX_INITIALIZER;

/* We store pointers to the session objects in 1024 buckets, indexed
   by the first two ZB32 encoded characters of the session id.  This
   requires 8k of memory for fast indexing which is not too much.  */
static session_t sessions[32][32];

/* We store pointers to the alias objects in 1024 buckets, indexed
   by the first two ZB32 encoded characters of the aslias id.  This
   requires 8k of memory for fast indexing which is not too much.  */
static session_alias_t aliases[32][32];

/* Total number of sessions in use.  This counter is used to quickly
   check whether we are allowed to create a new session.  */
static unsigned int sessions_in_use;

/* Because the session and alias objects have a fixed size, it is easy
   to reuse them.  */
static session_t unused_sessions;
static session_alias_t unused_aliases;


/*  Local prototypes  */
static gpg_error_t do_destroy_alias (const char *aliasid,
                                     session_alias_t alias);




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
  int i, a, b;

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
                /* Remove the aliases.  */
                for (i=0; i < MAX_ALIASES_PER_SESSION; i++)
                  if (sess->aliases[i])
                    {
                      session_alias_t alias = sess->aliases[i];
                      sess->aliases[i] = NULL;
                      do_destroy_alias (NULL, alias);
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
  int i;
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

  /* Just to be safe clear the other fields.  */
  sess->dict = NULL;
  for (i=0; i < MAX_ALIASES_PER_SESSION; i++)
    sess->aliases[i] = NULL;

  /* Init the dictionary.  */
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
  int i, a, b;

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

  /* Remove the aliases.  */
  for (i=0; i < MAX_ALIASES_PER_SESSION; i++)
    if (sess->aliases[i])
      {
        session_alias_t alias = sess->aliases[i];
        sess->aliases[i] = NULL;
        err = do_destroy_alias (NULL, alias);
        if (err)
          goto leave;
      }

  /* Remove the item from the hash table.  */
  if (prev)
    prev->next = sess->next;
  else
    sessions[a][b] = sess->next;
  sessions_in_use--;

  /* Remove the data. */
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



/* Store the session object for session SESSID at R_SESS.  On success
   the sessions are locked and the caller must unlock it.  The TTL has
   also been checked.  On failure NULL is stored at R_SESS and and
   error code is returned; the sessions are not locked in this case.  */
static gpg_error_t
get_session_object (const char *sessid, session_t *r_sess)
{
  gpg_error_t err;
  time_t now;
  session_t sess;
  int a, b;

  *r_sess = NULL;

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
      unlock_sessions ();
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  now = time (NULL);
  if (check_ttl (sess, now))
    {
      session_do_destroy (sessid, 0);
      unlock_sessions ();
      return gpg_error (GPG_ERR_NOT_FOUND);
    }
  sess->accessed = now;

  *r_sess = sess;

  return 0;
}



/* Create an alias for the session SESSID.  On return a malloced
   string with the alias is stored at R_ALIASID.  Note that only a few
   aliases may be created per session and that aliases are deleted
   with the session.  An alias is useful to reference a session to a
   remote service without given the remote service the ability to take
   over a session.  Obviously the alias id should only be used if it
   has been received from that service provider.  */
gpg_error_t
session_create_alias (const char *sessid, char **r_aliasid)
{
  gpg_error_t err;
  session_t sess;
  session_alias_t alias = alias;
  int malloced = 0;
  int aidx;
  char nonce[SESSID_RAW_LENGTH];
  char *p;
  int a, b;

  *r_aliasid = NULL;

  err = get_session_object (sessid, &sess);
  if (err)
    return err;

  for (aidx=0; aidx < MAX_ALIASES_PER_SESSION; aidx++)
    if (!sess->aliases[aidx])
      break;
  if (!(aidx < MAX_ALIASES_PER_SESSION))
    {
      err = gpg_error (GPG_ERR_LIMIT_REACHED);
      goto leave;
    }

  if (unused_aliases)
    {
      alias = unused_aliases;
      unused_aliases = alias->next;
      alias->next = NULL;
    }
  else
    {
      /* Note that the total number of aliases is bound by the maximum
         number of sessions.  */
      alias = xtrycalloc (1, sizeof *alias);
      if (!alias)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      malloced = 1;
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
  strcpy (alias->aliasid, p);
  *r_aliasid = p;

  alias->sess = sess;
  sess->aliases[aidx] = alias;

  /* Put the alias into the hash table.  */
  a = zb32_index (alias->aliasid[0]);
  b = zb32_index (alias->aliasid[1]);
  if ( a < 0 || a > 31 || b < 0 || b > 32)
    BUG ();
  alias->next = aliases[a][b];
  aliases[a][b] = alias;
  alias = NULL;

 leave:
  if (alias)
    {
      /* Push an unused session object back or release it.  */
      if (malloced)
        xfree (alias);
      else
        {
          alias->sess = NULL;
          alias->next = unused_aliases;
          unused_aliases = alias;
        }
    }
  if (err)
    {
      xfree (*r_aliasid);
      *r_aliasid = NULL;
    }
  unlock_sessions ();
  return err;
}


/* Internal version of session_destroy_alias.  This may be called in
   two modes: If ALIASID is not NULL this destroys the given alias.
   if ALIAS is not NULL, this alias object is directly destroyed in
   which case the caller mus have locked the sessions and make sure to
   remove the reference from the corresponding session object.  */
static gpg_error_t
do_destroy_alias (const char *aliasid, session_alias_t alias)
{
  gpg_error_t err = 0;
  int need_lock = !!aliasid;
  session_alias_t prev;
  int i;
  int a, b;

  if (aliasid && alias)
    BUG ();

  if (alias)
    {
      aliasid = alias->aliasid;
      alias = NULL;
    }

  if (strlen (aliasid) != SESSID_LENGTH
      || (a = zb32_index (aliasid[0])) < 0
      || (b = zb32_index (aliasid[1])) < 0)
    {
      return gpg_error (GPG_ERR_INV_NAME);
    }

  if (need_lock)
    {
      err = lock_sessions ();
      if (err)
        return err;
    }

  for (alias=aliases[a][b], prev=NULL; alias; prev=alias, alias=alias->next)
    if (!strcmp (alias->aliasid, aliasid))
      break;
  if (!alias)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* Remove the item from the hash table.  */
  if (prev)
    prev->next = alias->next;
  else
    aliases[a][b] = alias->next;

  /* Remove the reference from the session unless we are called with
     the alias object as input and thus do not have to take the lock.  */
  if (need_lock)
    {
      session_t sess = alias->sess;

      alias->sess = NULL;
      for (i=0; i < MAX_ALIASES_PER_SESSION; i++)
        if (sess->aliases[i] == alias)
          sess->aliases[i] = NULL;
    }

  /* Shove the item into the attic.  */
  alias->next = unused_aliases;
  unused_aliases = alias;

 leave:
  if (need_lock)
    unlock_sessions ();
  return err;
}


/* Destroy the alias ALIASID.  */
gpg_error_t
session_destroy_alias (const char *aliasid)
{
  return do_destroy_alias (aliasid, NULL);
}



/* Return the session id for the given aliasid.  */
gpg_error_t
session_get_sessid (const char *aliasid, char **r_sessid)
{
  gpg_error_t err = 0;
  session_alias_t alias;
  int a, b;

  *r_sessid = NULL;

  if (strlen (aliasid) != SESSID_LENGTH
      || (a = zb32_index (aliasid[0])) < 0
      || (b = zb32_index (aliasid[1])) < 0)
    {
      return gpg_error (GPG_ERR_INV_NAME);
    }

  err = lock_sessions ();
  if (err)
    return err;

  for (alias=aliases[a][b]; alias; alias=alias->next)
    if (!strcmp (alias->aliasid, aliasid))
      break;
  if (!alias || !alias->sess)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  *r_sessid = xtrystrdup (alias->sess->sessid);
  if (!*r_sessid)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }


 leave:
  unlock_sessions ();
  return err;
}



/* Update the data for session SESSID using the dictionary DICT.  If
   the value of a dictionary entry is the empty string, that entry is
   removed from the session. */
gpg_error_t
session_put (const char *sessid, keyvalue_t dict)
{
  gpg_error_t err;
  session_t sess;
  keyvalue_t kv;

  err = get_session_object (sessid, &sess);
  if (err)
    return err;

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
  session_t sess;
  keyvalue_t kv;

  err = get_session_object (sessid, &sess);
  if (err)
    return err;

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
