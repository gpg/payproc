/* account.c - Access to the account database.
 * Copyright (C) 2017 g10 Code GmbH
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

/* The Database used for accounts is pretty simple:
 *
 * CREATE TABLE account (
 *   account_id TEXT NOT NULL PRIMARY KEY,
 *   created TEXT NOT NULL,            -- Creation date
 *   updated TEXT NOT NULL,            -- Last Update
 *   email TEXT,                       -- The mail address
 *   verified INTEGER NOT NULL,        -- True when the mail
 *                                        has has been verified
 *   stripe_cus TEXT,                  -- The encrypted customer id.
 *   meta TEXT       -- Copy of the meta data as put into the journal.
 *                   -- This is also encrypted using the database key.
 * )
 *
 * CREATE TABLE pending (
 *   token TEXT NOT NULL PRIMARY KEY,
 *   email TEXT NOT NULL,
 *   created INTEGER NOT NULL,
 *   account_ref TEXT NOT NULL,
 *   FOREIGN KEY(account_ref) REFERENCES account(account_id)
 * );
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <npth.h>
#include <gcrypt.h>
#include <sqlite3.h>

#include "util.h"
#include "logging.h"
#include "payprocd.h"
#include "journal.h"
#include "membuf.h"
#include "dbutil.h"
#include "encrypt.h"
#include "account.h"


/* The name of the account database file.  */
static const char account_db_fname[] = "/var/lib/payproc/account.db";
static const char account_test_db_fname[] = "/var/lib/payproc-test/account.db";

/* The database handle used for the account database.  This handle
   may only used after a successful open_account_db call and not
   after a close_account_db call.  The lock variable is maintained by
   the mentioned open and close functions. */
static sqlite3 *account_db;
static npth_mutex_t account_db_lock = NPTH_MUTEX_INITIALIZER;

/* This is a prepared statement for the INSERT operation.  It is
   protected by account_db_lock.  */
static sqlite3_stmt *account_insert_stmt;

/* This is a prepared statement for the UPDATE operation.  It is
   protected by account_db_lock.  */
static sqlite3_stmt *account_update_stmt;

/* This is a prepared statement for the SELECT by REF operation.  It
   is protected by account_db_lock.  */
static sqlite3_stmt *account_select_stmt;




/* Create an account reference code and store it in BUFFER.  An
 * account reference code is a string with the prefix "A" followed by
 * 14 lower case letters of digits.  The user must provide a buffer of
 * sufficient length (ie. 16 bytes or more).  */
static void
make_account_id (char *buffer, size_t bufsize)
{
  static char codes[31] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'k', 'm',
                            'n', 'p', 'q', 'r', 's', 't', 'u', 'w', 'x', 'y',
                            'z' };
  unsigned char nonce[14];
  int i;

  if (bufsize < 16)
    BUG ();

  buffer[0] = 'A';
  gcry_create_nonce (nonce, sizeof nonce);
  for (i=0; i < sizeof nonce; i++)
    buffer[1+i] = codes[nonce[i] % 31];
  buffer [15] = 0;
}



/* Relinquishes the lock on the account handle and if DO_CLOSE is
 * true also close the database handle.  Note that we usually keep the
 * database open for the lifetime of the process.  */
static void
close_account_db (int do_close)
{
  int res;

  if (do_close && account_db)
    {
      res = sqlite3_close (account_db);
      if (res == SQLITE_BUSY)
        {
          sqlite3_finalize (account_insert_stmt);
          account_insert_stmt = NULL;
          sqlite3_finalize (account_update_stmt);
          account_update_stmt = NULL;
          sqlite3_finalize (account_select_stmt);
          account_select_stmt = NULL;
          res = sqlite3_close (account_db);
        }
      if (res)
        log_error ("failed to close the account db: %s\n",
                   sqlite3_errstr (res));
      account_db = NULL;
    }

  res = npth_mutex_unlock (&account_db_lock);
  if (res)
    log_fatal ("failed to release account db lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
}


/* This function opens or creates the account database.  If the
 * database is already open it merly takes a lock ion the handle. */
static gpg_error_t
open_account_db (void)
{
  int res;
  sqlite3_stmt *stmt;
  const char *db_fname = opt.livemode? account_db_fname:account_test_db_fname;

  res = npth_mutex_lock (&account_db_lock);
  if (res)
    log_fatal ("failed to acquire account db lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
  if (account_db)
    return 0; /* Good: Already open.  */

  /* Database has not yet been opened.  Open or create it, make sure
     the tables exist, and prepare the required statements.  We use
     our own locking instead of the more complex serialization sqlite
     would have to do. */

  res = sqlite3_open_v2 (db_fname,
                         &account_db,
                         (SQLITE_OPEN_READWRITE
                          | SQLITE_OPEN_CREATE
                          | SQLITE_OPEN_NOMUTEX),
                         NULL);
  if (res)
    {
      log_error ("error opening '%s': %s\n",
                 db_fname, sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  sqlite3_extended_result_codes (account_db, 1);


  /* Create the tables if needed.  */
  res = sqlite3_prepare_v2 (account_db,
                            "CREATE TABLE IF NOT EXISTS account (\n"
                            "account_id TEXT NOT NULL PRIMARY KEY,\n"
                            "email      TEXT,\n"
                            "verified   INTEGER NOT NULL,\n"
                            "created    TEXT NOT NULL,\n"
                            "updated    TEXT NOT NULL,\n"
                            "stripe_cus TEXT,\n"
                            "meta       TEXT"
                            ")",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error creating account table (prepare): %s\n",
                 sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (res != SQLITE_DONE)
    {
      log_error ("error creating account table: %s\n", sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* Prepare an insert statement.  */
  res = sqlite3_prepare_v2
    (account_db,
     "INSERT INTO account (account_id, verified, created, updated)\n"
     "            VALUES (?1,0,?2,?3)",
     -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing insert statement: %s\n",
                 sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  account_insert_stmt = stmt;

  /* Prepare an update statement.  */
  res = sqlite3_prepare_v2 (account_db,
                            "UPDATE account SET"
                            " updated = ?2,"
                            " stripe_cus = ?3,"
                            " email = ?4"
                            " WHERE account_id=?1",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing update statement: %s\n",
                 sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  account_update_stmt = stmt;

  /* Prepare a select statement.  */
  res = sqlite3_prepare_v2 (account_db,
                            "SELECT * FROM account WHERE account_id=?1",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing select statement: %s\n",
                 sqlite3_errstr (res));
      close_account_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  account_select_stmt = stmt;

  return 0;
}


/* Insert a new record into the account table.  No values are
 * required.  On success the account id is stored at R_ACCOUNT_ID. */
static gpg_error_t
new_account_record (char **r_account_id)
{
  int res;
  char account_id[16];
  char datetime_buf [DB_DATETIME_SIZE];

  *r_account_id = NULL;

 retry:
  make_account_id (account_id, sizeof account_id);

  sqlite3_reset (account_insert_stmt);

  if (1)
    res = sqlite3_bind_text (account_insert_stmt,
                             1, account_id, -1, SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (account_insert_stmt, /* created */
                             2, db_datetime_now (datetime_buf), -1,
                             SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (account_insert_stmt, /* updated */
                             3, datetime_buf, -1,
                             SQLITE_TRANSIENT);
  if (res)
    {
      log_error ("error binding a value for the account table: %s\n",
                 sqlite3_errstr (res));
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (account_insert_stmt);
  if (res == SQLITE_CONSTRAINT_PRIMARYKEY)
    goto retry;
  if (res == SQLITE_DONE)
    {
      *r_account_id = xtrystrdup (account_id);
      if (!*r_account_id)
        return gpg_error_from_syserror ();
      return 0;
    }

  log_error ("error inserting into the account table: %s (%d)\n",
             sqlite3_errstr (res), res);
  return gpg_error (GPG_ERR_GENERAL);
}


/* Update the row specified by 'account-id'.  Currently the value
 * '_stripe_cus' is put encrypted into the column stripe_cus and if
 * available the value 'Email' is but into the column email.  */
static gpg_error_t
update_account_record (keyvalue_t dict)
{
  gpg_error_t err;
  int res;
  char datetime_buf [DB_DATETIME_SIZE];
  const char *account_id;
  const char *stripe_cus;
  char *enc_stripe_cus = NULL;
  const char *email;

  account_id = keyvalue_get_string (dict, "account-id");
  if (!*account_id)
    {
      log_error ("%s: value for 'account-id' missing\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  email = keyvalue_get (dict, "Email");

  stripe_cus = keyvalue_get_string (dict, "_stripe_cus");
  if (!*stripe_cus)
    {
      log_error ("%s: value for '_stripe_cus' missing\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  err = encrypt_string (&enc_stripe_cus, stripe_cus,
                        (ENCRYPT_TO_DATABASE | ENCRYPT_TO_BACKOFFICE));
  if (err)
    {
      log_error ("encrypting the Stripe customer_id failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      goto leave;
    }

  sqlite3_reset (account_update_stmt);

  res = sqlite3_bind_text (account_update_stmt,
                           1, account_id, -1,
                           SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (account_update_stmt,
                             2, db_datetime_now (datetime_buf), -1,
                             SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (account_update_stmt,
                             3, enc_stripe_cus, -1,
                             SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (account_update_stmt,
                             4, email, -1,
                             SQLITE_TRANSIENT);
  if (res)
    {
      log_error ("error binding a value for the account table: %s\n",
                 sqlite3_errstr (res));
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  res = sqlite3_step (account_update_stmt);
  if (res == SQLITE_DONE)
    {
      if (!sqlite3_changes (account_db))
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          log_error ("error updating account table: %s\n", gpg_strerror (err));
        }
      else
        err = 0;
    }
  else
    log_error ("error updating account table: %s [%s (%d)]\n",
               gpg_strerror (err), sqlite3_errstr (res), res);

 leave:
  xfree (enc_stripe_cus);
  return err;
}



/*
 *   Public API
 */


/* Create a new account record and store the account id at
 * R_ACCOUNT_ID.  */
gpg_error_t
account_new_record (char **r_account_id)
{
  gpg_error_t err;

  *r_account_id = NULL;

  err = open_account_db ();
  if (err)
    return err;

  err = new_account_record (r_account_id);
  close_account_db (0);

  return err;
}


/* See update_account_record.  */
gpg_error_t
account_update_record (keyvalue_t dict)
{
  gpg_error_t err;

  err = open_account_db ();
  if (err)
    return err;

  err = update_account_record (dict);
  close_account_db (0);

  return err;
}
