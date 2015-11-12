/* preorder.c - Access to the preorder database.
 * Copyright (C) 2015 g10 Code GmbH
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

/* The Database used for preorders is pretty simple:  Just a single table:

   CREATE TABLE preorder (
     ref   TEXT NOT NULL PRIMARY KEY,  -- The "ABCDE" part of ABCDE-NN.
     refnn INTEGER NOT NULL,           -- The "NN"    part of ABCDE-NN
     created TEXT NOT NULL,            -- Timestamp
     paid TEXT,                        -- Timestamp of last payment
     npaid INTEGER NOT NULL,           -- Total number of payments
     amount TEXT NOT NULL,             -- with decimal digit; thus TEXT.
     currency TEXT NOT NULL,
     desc TEXT,   -- Description of the order
     email TEXT,  -- Optional mail address.
     meta TEXT    -- Using the format from the journal.
   )


  Expiring entries can be done using

     DELETE from preorder
     WHERE julianday(created) < julianday('now', '-30 days')
           AND paid IS NULL;

  this has not been implemented here but should be done at startup and
  once a day.  Note that 'paid' tracks actual payments using this ref.
  We do not delete it from the DB so that the ref can be used for
  recurring payments.

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
#include "preorder.h"


#define DB_DATETIME_SIZE 20 /* "1970-01-01 12:00:00" */


/* The name of the preorder database file.  */
static const char preorder_db_fname[] = "/var/lib/payproc/preorder.db";

/* The database handle used for the preorder database.  This handle
   may only used after a successful open_preorder_db call and not
   after a close_preorder_db call.  The lock variable is maintained by
   the mentioned open and close functions. */
static sqlite3 *preorder_db;
static npth_mutex_t preorder_db_lock = NPTH_MUTEX_INITIALIZER;

/* This is a prepared statement for the INSERT operation.  It is
   protected by preorder_db_lock.  */
static sqlite3_stmt *preorder_insert_stmt;

/* This is a prepared statement for the UPDATE operation.  It is
   protected by preorder_db_lock.  */
static sqlite3_stmt *preorder_update_stmt;

/* This is a prepared statement for the SELECT by REF operation.  It
   is protected by preorder_db_lock.  */
static sqlite3_stmt *preorder_select_stmt;

/* This is a prepared statement for the SELECT by REFNN operation.  It
   is protected by preorder_db_lock.  */
static sqlite3_stmt *preorder_selectrefnn_stmt;

/* This is a prepared statement for the SELECT all operation.  It
   is protected by preorder_db_lock.  */
static sqlite3_stmt *preorder_selectlist_stmt;




/* Create a Sepa-Ref field and store it in BUFFER.  The format is:

     AAAAA-NN

  with AAAAA being uppercase letters or digits and NN a value between
  10 and 99.  Thus the entire length of the returned string is 8.  We
  use a base 28 alphabet for the A values with the first A restricted
  to a letter.  Some letters are left out because they might be
  misrepresented due to OCR scanning.  There are about 11 million
  different values for AAAAA. */
static void
make_sepa_ref (char *buffer, size_t bufsize)
{
  static char codes[28] = { 'A', 'B', 'C', 'D', 'E', 'G', 'H', 'J',
                            'K', 'L', 'N', 'R', 'S', 'T', 'W', 'X',
                            'Y', 'Z', '0', '1', '2', '3', '4', '5',
                            '6', '7', '8', '9' };
  unsigned char nonce[5];
  int i;
  unsigned int n;

  if (bufsize < 9)
    BUG ();

  gcry_create_nonce (nonce, sizeof nonce);
  buffer[0] = codes[nonce[0] % 18];
  for (i=1; i < 5; i++)
    buffer[i] = codes[nonce[i] % 28];
  buffer[5] = '-';
  n = (((unsigned int)nonce[0] << 24) | (nonce[1] << 16)
       | (nonce[2] << 8) | nonce[3]);
  i = 10 + (n % 90);
  buffer [6] = '0' + i / 10;
  buffer [7] = '0' + i % 10;
  buffer [8] = 0;
}


/* Given a buffer of size DB_DATETIME_SIZE put the current time into it.  */
static char *
db_datetime_now (char *buffer)
{
#if DB_DATETIME_SIZE != TIMESTAMP_SIZE + 4
# error mismatching timestamp sizes
#endif
  get_current_time (buffer);
  /* "19700101T120000" to
     "1970-01-01 12:00:00" */
  buffer[19] = 0;
  buffer[18] = buffer[14];
  buffer[17] = buffer[13];
  buffer[16] = ':';
  buffer[15] = buffer[12];
  buffer[14] = buffer[11];
  buffer[13] = ':';
  buffer[12] = buffer[10];
  buffer[11] = buffer[9];
  buffer[10] = ' ';
  buffer[9] = buffer[7];
  buffer[8] = buffer[6];
  buffer[7] = '-';
  buffer[6] = buffer[5];
  buffer[5] = buffer[4];
  buffer[4] = '-';

  return buffer;
}




/* Relinquishes the lock on the database handle and if DO_CLOSE is
   true also close the database handle.  Note that we usually keep the
   database open for the lifetime of the process.  */
static void
close_preorder_db (int do_close)
{
  int res;

  if (do_close && preorder_db)
    {
      res = sqlite3_close (preorder_db);
      if (res == SQLITE_BUSY)
        {
          sqlite3_finalize (preorder_insert_stmt);
          preorder_insert_stmt = NULL;
          sqlite3_finalize (preorder_update_stmt);
          preorder_update_stmt = NULL;
          sqlite3_finalize (preorder_select_stmt);
          preorder_select_stmt = NULL;
          sqlite3_finalize (preorder_selectrefnn_stmt);
          preorder_selectrefnn_stmt = NULL;
          sqlite3_finalize (preorder_selectlist_stmt);
          preorder_selectlist_stmt = NULL;
          res = sqlite3_close (preorder_db);
        }
      if (res)
        log_error ("failed to close the preorder db: %s\n",
                   sqlite3_errstr (res));
      preorder_db = NULL;
    }

  res = npth_mutex_unlock (&preorder_db_lock);
  if (res)
    log_fatal ("failed to release preorder db lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
}


/* This function opens or creates the preorder database.  If the
   database is already open it merly takes a lock ion the handle. */
static gpg_error_t
open_preorder_db (void)
{
  int res;
  sqlite3_stmt *stmt;

  res = npth_mutex_lock (&preorder_db_lock);
  if (res)
    log_fatal ("failed to acquire preorder db lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
  if (preorder_db)
    return 0; /* Good: Already open.  */

  /* Database has not yet been opened.  Open or create it, make sure
     the tables exist, and prepare the required statements.  We use
     our own locking instead of the more complex serialization sqlite
     would have to do. */

  res = sqlite3_open_v2 (preorder_db_fname,
                         &preorder_db,
                         (SQLITE_OPEN_READWRITE
                          | SQLITE_OPEN_CREATE
                          | SQLITE_OPEN_NOMUTEX),
                         NULL);
  if (res)
    {
      log_error ("error opening '%s': %s\n",
                 preorder_db_fname, sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  sqlite3_extended_result_codes (preorder_db, 1);


  /* Create the tables if needed.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "CREATE TABLE IF NOT EXISTS preorder ("
                            "ref      TEXT NOT NULL PRIMARY KEY,"
                            "refnn    INTEGER NOT NULL,"
                            "created  TEXT NOT NULL,"
                            "paid TEXT,"
                            "npaid INTEGER NOT NULL,"
                            "amount   TEXT NOT NULL,"
                            "currency TEXT NOT NULL,"
                            "desc     TEXT,"
                            "email    TEXT,"
                            "meta     TEXT"
                            ")",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error creating preorder table (prepare): %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (res != SQLITE_DONE)
    {
      log_error ("error creating preorder table: %s\n", sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }

  /* Prepare an insert statement.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "INSERT INTO preorder VALUES ("
                            "?1,?2,?3,NULL,0,?4,?5,?6,?7,?8"
                            ")",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing insert statement: %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  preorder_insert_stmt = stmt;

  /* Prepare an update statement.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "UPDATE preorder SET"
                            " paid = ?2,"
                            " npaid = npaid + 1"
                            " WHERE ref=?1",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing update statement: %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  preorder_update_stmt = stmt;

  /* Prepare a select statement.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "SELECT * FROM preorder WHERE ref=?1",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing select statement: %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  preorder_select_stmt = stmt;

  /* Prepare a select-refnn statement.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "SELECT * FROM preorder "
                            "WHERE refnn=?1 ORDER BY ref",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing selectrefnn statement: %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  preorder_selectrefnn_stmt = stmt;

  /* Prepare a select-list statement.  */
  res = sqlite3_prepare_v2 (preorder_db,
                            "SELECT * FROM preorder "
                            "ORDER BY created DESC, refnn ASC",
                            -1, &stmt, NULL);
  if (res)
    {
      log_error ("error preparing select statement: %s\n",
                 sqlite3_errstr (res));
      close_preorder_db (1);
      return gpg_error (GPG_ERR_GENERAL);
    }
  preorder_selectlist_stmt = stmt;

  return 0;
}


/* Insert a record into the preorder table.  The values are taken from
   the dictionary at DICTP.  On return a Sepa-Ref value will have been
   inserted into it; that may happen even on error.  */
static gpg_error_t
insert_preorder_record (keyvalue_t *dictp)
{
  gpg_error_t err;
  int res;
  keyvalue_t dict = *dictp;
  char separef[9];
  char *buf;
  char datetime_buf [DB_DATETIME_SIZE];
  int retrycount = 0;

 retry:
  make_sepa_ref (separef, sizeof separef);
  err = keyvalue_put (dictp, "Sepa-Ref", separef);
  if (err)
    return err;
  dict = *dictp;

  sqlite3_reset (preorder_insert_stmt);

  separef[5] = 0;
  res = sqlite3_bind_text (preorder_insert_stmt,
                           1, separef, -1, SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_int (preorder_insert_stmt,
                            2, atoi (separef + 6));
  if (!res)
    res = sqlite3_bind_text (preorder_insert_stmt,
                             3, db_datetime_now (datetime_buf),
                             -1, SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (preorder_insert_stmt,
                             4, keyvalue_get_string (dict, "Amount"),
                             -1, SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (preorder_insert_stmt,
                             5, "EUR", -1, SQLITE_STATIC);
  if (!res)
    res = sqlite3_bind_text (preorder_insert_stmt,
                             6, keyvalue_get (dict, "Desc"),
                             -1, SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (preorder_insert_stmt,
                             7, keyvalue_get (dict, "Email"),
                             -1, SQLITE_TRANSIENT);
  if (!res)
    {
      buf = meta_field_to_string (dict);
      if (!buf)
        res = sqlite3_bind_null (preorder_insert_stmt, 8);
      else
        res = sqlite3_bind_text (preorder_insert_stmt, 8, buf, -1, es_free);
    }

  if (res)
    {
      log_error ("error binding a value for the preorder table: %s\n",
                 sqlite3_errstr (res));
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (preorder_insert_stmt);
  if (res == SQLITE_DONE)
    return 0;

  /* In case we hit the same primary key we need to retry.  This is
     limited to 11000 retries (~0.1% of the primary key space).  */
  if (res == SQLITE_CONSTRAINT_PRIMARYKEY && ++retrycount < 11000)
    goto retry;

  log_error ("error inserting into preorder table: %s (%d)\n",
             sqlite3_errstr (res), res);
  return gpg_error (GPG_ERR_GENERAL);
}


static gpg_error_t
get_text_column (sqlite3_stmt *stmt, int idx, int icol, const char *name,
                 keyvalue_t *dictp)
{
  gpg_error_t err;
  const char *s;

  s = sqlite3_column_text (stmt, icol);
  if (!s && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
    err = gpg_error (GPG_ERR_ENOMEM);
  else if (!strcmp (name, "Meta"))
    err = s? keyvalue_put_meta (dictp, s) : 0;
  else
    err = keyvalue_put_idx (dictp, name, idx, s);

  return err;
}


/* Put all columns into DICTP.  */
static gpg_error_t
get_columns (sqlite3_stmt *stmt, int idx, keyvalue_t *dictp)
{
  gpg_error_t err;
  char separef[9];
  const char *s;
  int i;

  s = sqlite3_column_text (stmt, 0);
  if (!s && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
    err = gpg_error (GPG_ERR_ENOMEM);
  else
    {
      strncpy (separef, s, 5);
      i = sqlite3_column_int (stmt, 1);
      if (!i && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
        err = gpg_error (GPG_ERR_ENOMEM);
      else if (i < 0 || i > 99)
        err = gpg_error (GPG_ERR_INV_DATA);
      else
        {
          snprintf (separef+5, 4, "-%02d", i);
          err = keyvalue_put_idx (dictp, "Sepa-Ref", idx, separef);
        }
    }

  if (!err)
    err = get_text_column (stmt, idx, 2, "Created", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 3, "Paid", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 4, "N-Paid", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 5, "Amount", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 6, "Currency", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 7, "Desc", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 8, "Email", dictp);
  if (!err)
    err = get_text_column (stmt, idx, 9, "Meta", dictp);

  return err;
}


/* Format columns and put the formatted line into DICTP under the
   key "D[idx]".  */
static gpg_error_t
format_columns (sqlite3_stmt *stmt, int idx, keyvalue_t *dictp)
{
  gpg_error_t err;
  membuf_t mb;
  const char *s;
  int i;

  init_membuf (&mb, 512);

  s = sqlite3_column_text (stmt, 0);
  if (!s && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
    {
      err = gpg_error (GPG_ERR_ENOMEM);
      goto leave;
    }

  i = sqlite3_column_int (stmt, 1);
  if (!i && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
    {
      err = gpg_error (GPG_ERR_ENOMEM);
      goto leave;
    }
  put_membuf_printf (&mb, "|%s-%02d", s, i);

  for (i = 2; i <= 9; i++)
    {
      put_membuf_chr (&mb, '|');
      s = sqlite3_column_text (stmt, i);
      if (!s && sqlite3_errcode (preorder_db) == SQLITE_NOMEM)
        {
          err = gpg_error (GPG_ERR_ENOMEM);
          goto leave;
        }
      if (!s)
        ;
      else if (strchr (s, '|'))
        {
          for (; *s; s++)
            if (*s == '|')
              put_membuf_str (&mb, "=7C");
            else
              put_membuf_chr (&mb, *s);
        }
      else
        put_membuf_str (&mb, s);
    }
  put_membuf_chr (&mb, '|');

  {
    char *p;

    put_membuf_chr (&mb, 0);
    p = get_membuf (&mb, NULL);
    if (!p)
      err = gpg_error_from_syserror ();
    else
      {
        err = keyvalue_put_idx (dictp, "D", idx, p);
        xfree (p);
      }
  }

 leave:
  xfree (get_membuf (&mb, NULL));
  return err;
}


/* Get a record from the preorder table.  The values are stored at the
   dictionary at DICTP.  */
static gpg_error_t
get_preorder_record (const char *ref, keyvalue_t *dictp)
{
  gpg_error_t err;
  int res;

  if (strlen (ref) != 5)
    return gpg_error (GPG_ERR_INV_LENGTH);

  sqlite3_reset (preorder_select_stmt);

  res = sqlite3_bind_text (preorder_select_stmt,
                           1, ref, 5, SQLITE_TRANSIENT);
  if (res)
    {
      log_error ("error binding a value for the preorder table: %s\n",
                 sqlite3_errstr (res));
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (preorder_select_stmt);
  if (res == SQLITE_ROW)
    {
      res = SQLITE_OK;
      err = get_columns (preorder_select_stmt, -1, dictp);
    }
  else if (res == SQLITE_DONE)
    {
      res = SQLITE_OK;
      err = gpg_error (GPG_ERR_NOT_FOUND);
    }
  else
    err = gpg_error (GPG_ERR_GENERAL);

  if (err)
    {
      if (res == SQLITE_OK)
        log_error ("error selecting from preorder table: %s\n",
                   gpg_strerror (err));
      else
        log_error ("error selecting from preorder table: %s [%s (%d)]\n",
                   gpg_strerror (err), sqlite3_errstr (res), res);
    }
  return err;
}


/* List records from the preorder table.  The values are stored at the
   dictionary at DICTP with a D[n] key.  The number of records is
   stored at R_COUNT.  */
static gpg_error_t
list_preorder_records (const char *refnn,
                       keyvalue_t *dictp, unsigned int *r_count)
{
  gpg_error_t err;
  sqlite3_stmt *stmt;
  int count = 0;
  int res;

  stmt = *refnn? preorder_selectrefnn_stmt : preorder_selectlist_stmt;

  sqlite3_reset (stmt);

  if (*refnn)
    {
      res = sqlite3_bind_text (stmt, 1, refnn, -1, SQLITE_TRANSIENT);
      if (res)
        {
          log_error ("error binding a value for the preorder table: %s\n",
                     sqlite3_errstr (res));
          return gpg_error (GPG_ERR_GENERAL);
        }
    }

 next:
  res = sqlite3_step (stmt);
  if (res == SQLITE_ROW)
    {
      res = SQLITE_OK;
      err = format_columns (stmt, count, dictp);
      if (!err)
        {
          if (++count)
            goto next;
          err = gpg_error (GPG_ERR_WOULD_WRAP);
        }
    }
  else if (res == SQLITE_DONE)
    {
      res = SQLITE_OK;
      err = 0;
    }
  else
    err = gpg_error (GPG_ERR_GENERAL);

  if (err)
    {
      if (res == SQLITE_OK)
        log_error ("error selecting from preorder table: %s\n",
                   gpg_strerror (err));
      else
        log_error ("error selecting from preorder table: %s [%s (%d)]\n",
                   gpg_strerror (err), sqlite3_errstr (res), res);
    }
  else
    *r_count = count;
  return err;
}


/* Update a row specified by REF in the preorder table.  Also update
   the timestamp field at DICTP. */
static gpg_error_t
update_preorder_record (const char *ref, keyvalue_t *dictp)
{
  gpg_error_t err;
  int res;
  char datetime_buf [DB_DATETIME_SIZE];

  if (strlen (ref) != 5)
    return gpg_error (GPG_ERR_INV_LENGTH);

  sqlite3_reset (preorder_update_stmt);

  res = sqlite3_bind_text (preorder_update_stmt,
                           1, ref, 5,
                           SQLITE_TRANSIENT);
  if (!res)
    res = sqlite3_bind_text (preorder_update_stmt,
                             2, db_datetime_now (datetime_buf), -1,
                             SQLITE_TRANSIENT);
  if (res)
    {
      log_error ("error binding a value for the preorder table: %s\n",
                 sqlite3_errstr (res));
      return gpg_error (GPG_ERR_GENERAL);
    }

  res = sqlite3_step (preorder_update_stmt);
  if (res == SQLITE_DONE)
    {
      if (!sqlite3_changes (preorder_db))
        err = gpg_error (GPG_ERR_NOT_FOUND);
      else
        err = 0;
    }
  else
    err = gpg_error (GPG_ERR_GENERAL);

  if (!err)
    err = keyvalue_put (dictp, "_timestamp", datetime_buf);

  if (gpg_err_code (err) == GPG_ERR_GENERAL)
    log_error ("error updating preorder table: %s [%s (%d)]\n",
               gpg_strerror (err), sqlite3_errstr (res), res);
  else
    log_error ("error updating preorder table: %s\n",
               gpg_strerror (err));
  return err;
}


/* Create a new preorder record and store it.  Inserts a "Sepa-Ref"
   into DICT.  */
gpg_error_t
preorder_store_record (keyvalue_t *dictp)
{
  gpg_error_t err;

  err = open_preorder_db ();
  if (err)
    return err;

  err = insert_preorder_record (dictp);
  close_preorder_db (0);

  return err;
}


/* Take the Sepa-Ref from DICTP, fetch the row, and update DICTP with
   that data.  On error return an error code.  Note that DICTP may
   even be changed on error.  */
gpg_error_t
preorder_get_record (keyvalue_t *dictp)
{
  gpg_error_t err;
  char separef[9];
  const char *s;
  char *p;

  s = keyvalue_get (*dictp, "Sepa-Ref");
  if (!s || strlen (s) >= sizeof separef)
    return gpg_error (GPG_ERR_INV_LENGTH);
  strcpy (separef, s);
  p = strchr (separef, '-');
  if (p)
    *p = 0;

  err = open_preorder_db ();
  if (err)
    return err;

  err = get_preorder_record (separef, dictp);

  close_preorder_db (0);

  return err;
}


/* Take the number Sepa-Ref from DICTP, fetch the row, and update DICTP with
   that data.  On error return an error code.  Note that DICTP may
   even be changed on error.  */
gpg_error_t
preorder_list_records (keyvalue_t *dictp, unsigned int *r_count)
{
  gpg_error_t err;
  char refnn[3];
  const char *s;

  *r_count = 0;
  s = keyvalue_get (*dictp, "Refnn");
  if (s)
    {
      if (strlen (s) != 2)
        return gpg_error (GPG_ERR_INV_LENGTH);
      strcpy (refnn, s);
    }
  else
    *refnn = 0;

  err = open_preorder_db ();
  if (err)
    return err;

  err = list_preorder_records (refnn, dictp, r_count);

  close_preorder_db (0);

  return err;
}


/* Take the Sepa-Ref from NEWDATA and update the corresponding row with
   the other data from NEWDATA.  On error return an error code.  */
gpg_error_t
preorder_update_record (keyvalue_t newdata)
{
  gpg_error_t err;
  char separef[9];
  const char *s;
  char *p;
  keyvalue_t olddata = NULL;

  s = keyvalue_get (newdata, "Sepa-Ref");
  if (!s || strlen (s) >= sizeof separef)
    return gpg_error (GPG_ERR_INV_LENGTH);
  strcpy (separef, s);
  p = strchr (separef, '-');
  if (p)
    *p = 0;

  err = open_preorder_db ();
  if (err)
    return err;

  err = get_preorder_record (separef, &olddata);
  if (err)
    goto leave;

  /* Update OLDDATA with the actual amount so that we can put the
     correct amount into the log.  */
  err = keyvalue_put (&olddata, "Amount",
                      keyvalue_get_string (newdata, "Amount"));
  if (err)
    goto leave;

  /* We pass OLDDATA so that _timestamp will be set.  */
  err = update_preorder_record (separef, &olddata);
  if (err)
    goto leave;

  /* FIXME: Unfortunately the journal function creates its own
     timestamp.  */
  jrnl_store_charge_record (&olddata, PAYMENT_SERVICE_SEPA);


 leave:
  close_preorder_db (0);
  keyvalue_release (olddata);

  return err;
}
