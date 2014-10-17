/* payproc-stat.c - Create statistics from Payproc journals
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

/*

  This program creates an output file in a line oriented format where
  the fields of a line are delimited by colons.  The file is sorted by
  YEAR and MONTH and with no duplicate values.  Each line describes
  statistics for the indicated year and month.  The line format is:

    YEAR:MONTH:X1:TAG:TAGLNR:X2:N:EURO:NYR:EUROYR:

  YEAR  - the year (eg. 2014)
  MONTH - the month (1..12, with or without a leading zero)
  X1    - Reserved
  TAG   - An internal value used by this program to allow updating of
          the statistics file.  The tag consist of the variable part
          of the journal file and is expected to be a sortable date string.
  TAGLNR- The second part of the tag (the line number)
  X2    - Reserved
  N     - The number of charge records in that month
  EURO  - The total amount from the charge records in that month.
  NYR   - The number of charge records in that year
  EUROYR- The total amount in that year up to this month.

 */



#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>
#include <assert.h>
#include <ctype.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"
#include "estream.h"
#include "jrnl-fields.h"

/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',
    oIgnoreCase = 'i',
    oSelect     = 'S',
    oUpdate     = 'u',

    oSeparator  = 500,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, "@\nOptions:\n "),

  ARGPARSE_s_n (oVerbose,"verbose",  "verbose diagnostics"),
  ARGPARSE_s_n (oIgnoreCase, "ignore-case", "ignore case in record matching"),
  ARGPARSE_s_s (oSeparator, "separator", "|CHAR|use CHAR as output separator"),
  ARGPARSE_s_s (oSelect, "select",   "|EXPR|output records matching EXPR"),
  ARGPARSE_s_s (oUpdate, "update",   "|FILE|update FILE and print to stdout"),

  ARGPARSE_end ()
};


/* List of the journal field names.  */
static char *jrnl_field_names[] =
  {
    "_lnr", /* virtual field.  */
    JRNL_FIELD_NAME_DATE,
    JRNL_FIELD_NAME_TYPE,
    JRNL_FIELD_NAME_LIVE,
    JRNL_FIELD_NAME_CURRENCY,
    JRNL_FIELD_NAME_AMOUNT,
    JRNL_FIELD_NAME_DESC,
    JRNL_FIELD_NAME_MAIL,
    JRNL_FIELD_NAME_META,
    JRNL_FIELD_NAME_LAST4,
    JRNL_FIELD_NAME_SERVICE,
    JRNL_FIELD_NAME_ACCOUNT,
    JRNL_FIELD_NAME_CHARGEID,
    JRNL_FIELD_NAME_TXID,
    JRNL_FIELD_NAME_RTXID,
    JRNL_FIELD_NAME_EURO
  };


/* Select operators.  */
typedef enum
  {
    SELECT_SAME,
    SELECT_NOTSAME,
    SELECT_SUB,
    SELECT_NOTSUB,
    SELECT_EMPTY,
    SELECT_NOTEMPTY,
    SELECT_EQ, /* Numerically equal.  */
    SELECT_NE, /* Numerically not equal.  */
    SELECT_LE,
    SELECT_GE,
    SELECT_LT,
    SELECT_GT
  } select_op_t;


/* Defintion for a select expression.  */
typedef struct selectexpr_s
{
  struct selectexpr_s *next;
  int meta;
  unsigned int fnr;
  select_op_t op;
  const char *value;  /* Points into NAME.  */
  long numvalue;
  char name[1];
} *selectexpr_t;


/* Command line options.  */
static struct
{
  int verbose;
  int separator;
  int ignorecase;
  selectexpr_t selectexpr;
  const char *updatefile;
} opt;


/* Maximum lenbth of the tag without the line number.  */
#define MAX_TAGLEN 20

/* Structure for an output record.  */
struct stat_record_s
{
  int year;
  int month;
  unsigned int n;
  unsigned long euro;
  unsigned long cent;
  unsigned int nyr;
  unsigned long euroyr;
  unsigned long centyr;
  char tag[MAX_TAGLEN+1];
  unsigned int taglnr;
  int update;      /* Set if initialized by read_stat_file.  */
};
typedef struct stat_record_s *stat_record_t;
typedef const struct stat_record_s *const_stat_record_t;

/* A century of stat rceords should be more than sufficient.  */
static struct stat_record_s statrecords[100*12];


/* Total number of selected records so far.  */
static unsigned int recordcount;


/* Local prototypes.  */
static int parse_fieldname (char *name, int *r_meta, unsigned int *r_fnr);
static selectexpr_t parse_selectexpr (const char *expr);
static void one_file (const char *fname);
static void read_stat_file (const char *fname);
static void postprocess_statrecords (void);
static void print_output (void);



static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "payproc-stat"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 19: p = "Please report bugs to bugs@g10code.com.\n"; break;
    case 1:
    case 40: p = "Usage: payproc-stat [options] FILES (-h for help)"; break;
    case 41: p = ("Syntax: payproc-stat [options] FILES\n"
                  "Print statistics from payproc journal files\n"); break;
    default: p = NULL; break;
    }
  return p;
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  selectexpr_t se, se2;

  opt.separator = ':';

  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("payproc-stat", JNLIB_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  es_init ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  while (optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose:  opt.verbose++; break;
        case oIgnoreCase: opt.ignorecase = 1; break;
        case oSeparator:
          if (strlen (pargs.r.ret_str) > 1)
            log_error ("--separator takes only a single character\n");
          else
            opt.separator = *pargs.r.ret_str;
          break;

	case oSelect:
          se = parse_selectexpr (pargs.r.ret_str);
          if (!se)
            ;
	  else if (!(se2 = opt.selectexpr))
	    opt.selectexpr = se;
	  else
	    {
	      for (; se2->next; se2 = se2->next)
		;
	      se2->next = se;
	    }
	  break;

        case oUpdate:
          opt.updatefile = pargs.r.ret_str;
          break;

        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  if (opt.updatefile)
    read_stat_file (opt.updatefile);

  if (log_get_errorcount (0))
    exit (1);

  /* Process all files.  */
  for (; argc; argc--, argv++)
    {
      one_file (*argv);
    }

  if (!log_get_errorcount (0))
    {
      postprocess_statrecords ();
      print_output ();
    }

  return !!log_get_errorcount (0);
}


/* Parse a field name.  Returns 0 on success.  */
static int
parse_fieldname (char *name, int *r_meta, unsigned int *r_fnr)
{
  const char *s;
  char *p;

  *r_meta = 0;
  *r_fnr = 0;

  s = name;
  if (*s == '[')
    {
      *r_meta = 1;
      for (p=name, ++s; *s && *s != ']';)
        *p++ = *s++;
      *p = 0;
      if (*s != ']' || s[1] || !*name)
        {
          log_error ("field '%s': invalid meta field name syntax\n", name);
          return -1;
        }
    }
  else
    {
      if (digitp (s))
        {
          *r_fnr = atoi (s);
          if (*r_fnr >= DIM(jrnl_field_names))
            {
              log_error ("field '%s': field number out of range\n", name);
              return -1;
            }
          *name = 0;
        }
      else
        {
          for (*r_fnr = 0; *r_fnr < DIM(jrnl_field_names); ++*r_fnr)
            if (!strcmp (s, jrnl_field_names[*r_fnr]))
              break;
          if (*r_fnr >= DIM(jrnl_field_names))
            {
              log_error ("field '%s': unknown name\n", s);
              return -1;
            }
        }
    }

  return 0;
}


/* Parse a select expression.  Supported expressions are:

   [<ws>]NAME[<ws>]<op>[<ws>]VALUE[<ws>]

   NAME and VALUE may not be the empty string. <ws> indicates white
   space.  [] indicates optional parts.  If VALUE starts with one of
   the characters used in any <op> a space after the <op> is required.
   Valid <op> are:

      =~  Substring must match
      !~  Substring must not match
      =   The full string must match
      <>  The full string must not match
      ==  The numerical value must match
      !=  The numerical value must not match
      <=  The numerical value of the field must be LE than the value.
      <   The numerical value of the field must be LT than the value.
      >=  The numerical value of the field must be GT than the value.
      >=  The numerical value of the field must be GE than the value.
      -n  True if value is not empty.
      -z  True if value is empty.

      Numerical values are computed as long int.  */
static selectexpr_t
parse_selectexpr (const char *expr)
{
  selectexpr_t se;
  const char *s0, *s;

  while (*expr == ' ' || *expr == '\t')
    expr++;

  se = xmalloc (sizeof *se + strlen (expr));
  strcpy (se->name, expr);
  se->next = NULL;

  s = strpbrk (expr, "=<>!~-");
  if (!s || s == expr )
    {
      log_error ("no field name given for select\n");
      return NULL;
    }
  s0 = s;

  if (!strncmp (s, "=~", 2))
    {
      se->op = SELECT_SUB;
      s += 2;
    }
  else if (!strncmp (s, "!~", 2))
    {
      se->op = SELECT_NOTSUB;
      s += 2;
    }
  else if (!strncmp (s, "<>", 2))
    {
      se->op = SELECT_NOTSAME;
      s += 2;
    }
  else if (!strncmp (s, "==", 2))
    {
      se->op = SELECT_EQ;
      s += 2;
    }
  else if (!strncmp (s, "!=", 2))
    {
      se->op = SELECT_NE;
      s += 2;
    }
  else if (!strncmp (s, "<=", 2))
    {
      se->op = SELECT_LE;
      s += 2;
    }
  else if (!strncmp (s, ">=", 2))
    {
      se->op = SELECT_GE;
      s += 2;
    }
  else if (!strncmp (s, "<", 1))
    {
      se->op = SELECT_LT;
      s += 1;
    }
  else if (!strncmp (s, ">", 1))
    {
      se->op = SELECT_GT;
      s += 1;
    }
  else if (!strncmp (s, "=", 1))
    {
      se->op = SELECT_SAME;
      s += 1;
    }
  else if (!strncmp (s, "-z", 2))
    {
      se->op = SELECT_EMPTY;
      s += 2;
    }
  else if (!strncmp (s, "-n", 2))
    {
      se->op = SELECT_NOTEMPTY;
      s += 2;
    }
  else
    {
      log_error ("invalid select operator\n");
      return NULL;
    }

  /* We require that a space is used if the value starts with any of
     the operator characters.  */
  if (se->op == SELECT_EMPTY || se->op == SELECT_NOTEMPTY)
    ;
  else if (strchr ("=<>!~", *s))
    {
      log_error ("invalid select operator\n");
      return NULL;
    }

  while (*s == ' ' || *s == '\t')
    s++;

  if (se->op == SELECT_EMPTY || se->op == SELECT_NOTEMPTY)
    {
      if (*s)
        {
          log_error ("value given for -n or -z\n");
          return NULL;
        }
    }
  else
    {
      if (!*s)
        {
          log_error ("no value given for select\n");
          return NULL;
        }
    }

  se->name[s0 - expr] = 0;
  trim_spaces (se->name);
  if (!se->name[0])
    {
      log_error ("no field name given for select\n");
      return NULL;
    }

  trim_spaces (se->name + (s - expr));
  se->value = se->name + (s - expr);
  if (!se->value[0] && !(se->op == SELECT_EMPTY || se->op == SELECT_NOTEMPTY))
    {
      log_error ("no value given for select\n");
      return NULL;
    }

  if (parse_fieldname (se->name, &se->meta, &se->fnr))
    return NULL;

  se->numvalue = strtol (se->value, NULL, 10);

  return se;
}


/* Return true if the record RECORD has been selected.  Note that
   selection on meta fields is not yet functional.  */
static int
select_record_p (char **field, int nfields, unsigned int lnr)
{
  char linenostr[20];
  selectexpr_t se;
  const char *value;
  size_t selen, valuelen;
  long numvalue;
  int result = 1;

  *linenostr = 0;

  for (se=opt.selectexpr; se; se = se->next)
    {
      if (se->meta)
        {
          log_info ("meta fields in selects are not yet supported\n");
          continue;
        }
      else if (!se->fnr)
        {
          if (!*linenostr)
            snprintf (linenostr, sizeof linenostr, "%u", lnr);
          value = linenostr;
        }
      else if (se->fnr-1 < nfields)
        value = field[se->fnr-1];
      else
        {
          log_debug ("oops: fieldno out of range at %d\n", __LINE__);
          continue;
        }

      if (!*value)
        {
          /* Field is empty.  */
          switch (se->op)
            {
            case SELECT_NOTSAME:
            case SELECT_NOTSUB:
            case SELECT_NE:
            case SELECT_EMPTY:
              result = 1;
              break;
            default:
              result = 0;
              break;
            }
        }
      else /* Field has a value.  */
        {
          valuelen = strlen (value);
          numvalue = strtol (value, NULL, 10);
          selen = strlen (se->value);

          switch (se->op)
            {
            case SELECT_SAME:
              if (opt.ignorecase)
                result = (valuelen==selen && !memicmp (value,se->value,selen));
              else
                result = (valuelen==selen && !memcmp (value,se->value,selen));
              break;
            case SELECT_NOTSAME:
              if (opt.ignorecase)
                result = !(valuelen==selen && !memicmp (value,se->value,selen));
              else
                result = !(valuelen==selen && !memcmp (value,se->value,selen));
              break;
            case SELECT_SUB:
              if (opt.ignorecase)
                result = !!memistr (value, valuelen, se->value);
              else
                result = !!memstr (value, valuelen, se->value);
              break;
            case SELECT_NOTSUB:
              if (opt.ignorecase)
                result = !memistr (value, valuelen, se->value);
              else
                result = !memstr (value, valuelen, se->value);
              break;
            case SELECT_EMPTY:
              result = !valuelen;
              break;
            case SELECT_NOTEMPTY:
              result = !!valuelen;
              break;
            case SELECT_EQ:
              result = (numvalue == se->numvalue);
              break;
            case SELECT_NE:
              result = (numvalue != se->numvalue);
              break;
            case SELECT_GT:
              result = (numvalue > se->numvalue);
              break;
            case SELECT_GE:
              result = (numvalue >= se->numvalue);
              break;
            case SELECT_LT:
              result = (numvalue < se->numvalue);
              break;
            case SELECT_LE:
              result = (numvalue <= se->numvalue);
              break;
            }
        }
      if (!result)
        break;
    }

  return result;
}


/* Find a stat record for the given year and month.  Create a new one
   if we do not yet have any record for that date.  Terminates the
   process if the record table is exhausted. */
static stat_record_t
find_stat_record (int year, int month)
{
  int i;

  assert (year && month);
  for (i=0; i < DIM (statrecords); i++)
    if (statrecords[i].year == year && statrecords[i].month == month)
      return statrecords + i;
  /* Note yet.  Find an empty one.  */
  for (i=0; i < DIM (statrecords); i++)
    if (!statrecords[i].year)
      {
        statrecords[i].year = year;
        statrecords[i].month = month;
        return statrecords + i;
      }
  log_fatal ("table would overflow - more than different %u years\n",
             (unsigned int)DIM (statrecords)/12);
}


/* Process one journal line.  LINE has no trailing LF.  The function
   may change LINE.  */
static int
one_line (const char *fname, unsigned int lnr, const char *tag, char *line)
{
  char *field[NO_OF_JRNL_FIELDS];
  int nfields = 0;
  int year, month;
  const char *s;
  unsigned long euro, cent;
  stat_record_t rec;

  /* Parse into fields.  */
  while (line && nfields < DIM(field))
    {
      field[nfields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }
  if (nfields < 12)  /* Early versions had only 12 fields.  */
    {
      log_error ("%s:%u: not enough fields - not a Payproc journal?\n",
                 fname, lnr);
      return -1;
    }

  if (strcmp (field[JRNL_FIELD_TYPE], "C"))
    return 0;  /* We only care about charge records.  */

  if (nfields <= JRNL_FIELD_EURO)
    {
      log_error ("%s:%u: no \"euro\" field in charge record\n", fname, lnr);
      return -1;
    }

  year  = atoi_4 (field[JRNL_FIELD_DATE]);
  month = atoi_2 (field[JRNL_FIELD_DATE] + 4);
  if (year < 2000 || year > 9999 || month < 1 || month > 12 )
    {
      log_error ("%s:%u: invalid date field - not a Payproc journal?\n",
                 fname, lnr);
      return -1;
    }

  if (opt.selectexpr && !select_record_p (field, nfields, lnr))
    return 0;  /* Not selected.  */

  s = field[JRNL_FIELD_EURO];
  euro = strtoul (s, NULL, 10);
  s = strchr (s, '.');
  cent = s? strtoul (s+1, NULL, 10) : 0;

  rec = find_stat_record (year, month);
  if (rec->update)
    {
      /* A record already exists.  Check whether we need to update it.
         We do this if the tag is newer or if the tag is identical and
         the line number is newer.  */
      if ((!strcmp (tag, rec->tag) && lnr > rec->taglnr)
          || (strcmp (tag, rec->tag) > 0))
        {
          strcpy (rec->tag, tag);
          rec->taglnr = lnr;
          rec->n++;
          rec->euro += euro;
          rec->cent += cent;
        }
    }
  else /* Standard mode or new year/month in update mode. */
    {
      if (*rec->tag && strcmp (rec->tag, tag) > 0)
        {
          log_error ("%s:%u: tag already used in an older input file\n",
                     fname, lnr);
          return -1;
        }

      if (!strcmp (rec->tag, tag))
        {
          if (lnr > rec->taglnr)
            rec->taglnr = lnr;
        }
      else
        {
          strcpy (rec->tag, tag);
          rec->taglnr = lnr;
        }

      rec->n++;
      rec->euro += euro;
      rec->cent += cent;
    }

  recordcount++;

  return 0;
}


static void
one_file (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  char *buffer = NULL;
  size_t buflen = 0;
  ssize_t nread;
  unsigned int lnr = 0;
  char tagbuf[MAX_TAGLEN+1];
  int i;
  const char *s0, *s;


  /* Fixme: We should process the files in the order of the tags.  */

  s0 = strrchr (fname, '/');
  if (!s0)
    s0 = fname;
  s0 = strchr (s0, '-');
  i = 0;
  if (s0)
    {
      for (s=s0+1; *s && *s != '.' && i < sizeof tagbuf -1 ; s++)
        {
          if (!(*s & 0x80) && isdigit (*s))
            tagbuf[i++] = *s;
          else
            break;
        }
      tagbuf[i] = 0;
    }
  if (i < 4 || (*s && *s != '.'))
    {
      log_error ("error processing file '%s': Invalid name\n", fname);
      return;
    }


  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n", fname, gpg_strerror (err));
      return;
    }
  if (opt.verbose)
    log_info ("processing '%s'\n", fname);

  while ((nread = es_read_line (fp, &buffer, &buflen, NULL)) > 0)
    {
      lnr++;
      if (buffer[nread-1] == '\n')
        buffer[--nread] = 0;
      if (nread && buffer[nread-1] == '\r')
        buffer[--nread] = 0;
      if (nread && one_line (fname, lnr, tagbuf, buffer))
        goto leave;
    }
  if (nread < 0)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
    }

 leave:
  es_free (buffer);
  es_fclose (fp);
}


/* Process one line from a stats file.  LINE has no trailing LF.  The
   function may change LINE.  */
static int
read_stat_line (const char *fname, unsigned int lnr, char *line)
{
  char *field[12];
  int nfields = 0;
  int year, month;
  const char *s;
  const char *tag;
  unsigned int taglnr;
  unsigned long euro, cent, euroyr, centyr;
  stat_record_t rec;

  /* Parse into fields.  */
  while (line && nfields < DIM(field))
    {
      field[nfields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }
  if (nfields < 9)
    {
      log_error ("%s:%u: not enough fields - not a Payproc stat file?\n",
                 fname, lnr);
      return -1;
    }

  year  = atoi (field[0]);
  month = atoi (field[1]);
  if (year < 2000 || year > 9999 || month < 1 || month > 12 )
    {
      log_error ("%s:%u: invalid date field - not a Payproc stat file?\n",
                 fname, lnr);
      return -1;
    }

  tag = field[3];
  if (!*tag || strlen (tag) > MAX_TAGLEN)
    {
      log_error ("%s:%u: no tag or tag too long\n", fname, lnr);
      return -1;
    }
  taglnr = atoi (field[4]);

  s = field[7];
  euro = strtoul (s, NULL, 10);
  s = strchr (s, '.');
  cent = s? strtoul (s+1, NULL, 10) : 0;

  s = field[9];
  euroyr = strtoul (s, NULL, 10);
  s = strchr (s, '.');
  centyr = s? strtoul (s+1, NULL, 10) : 0;

  rec = find_stat_record (year, month);
  /* We always expect a new clean record - if not the input file has a
     double year/month line.  */
  if (*rec->tag)
    {
      log_error ("%s:%u: duplicated entry\n", fname, lnr);
      return -1;
    }
  strcpy (rec->tag, tag);
  rec->taglnr = taglnr;

  rec->n = strtoul (field[6], NULL, 10);
  rec->euro = euro;
  rec->cent = cent;
  rec->nyr = strtoul (field[8], NULL, 10);
  rec->euroyr = euroyr;
  rec->centyr = centyr;
  rec->update = 1;

  return 0;
}


/* Read an existing stat file and records its values in the
   statrecords.  */
static void
read_stat_file (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  char *buffer = NULL;
  size_t buflen = 0;
  ssize_t nread;
  unsigned int lnr = 0;

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n", fname, gpg_strerror (err));
      return;
    }
  if (opt.verbose)
    log_info ("reading '%s'\n", fname);

  while ((nread = es_read_line (fp, &buffer, &buflen, NULL)) > 0)
    {
      lnr++;
      if (buffer[nread-1] == '\n')
        buffer[--nread] = 0;
      if (nread && buffer[nread-1] == '\r')
        buffer[--nread] = 0;
      if (nread && read_stat_line (fname, lnr, buffer))
        goto leave;
    }
  if (nread < 0)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
    }

 leave:
  es_free (buffer);
  es_fclose (fp);
}


/* Sort the records.  */
static int
sort_statrecords_cmp (const void *xa, const void *xb)
{
  const_stat_record_t a = xa;
  const_stat_record_t b = xb;

  if (a->year == b->year)
    {
      if (a->month == b->month)
        return 0;
      else if (a->month > b->month)
        return 1;
      else
        return -1;
    }
  else if (a->year > b->year)
    return 1;
  else
    return -1;
}


/* Sort the records in reverse order.  */
static int
sort_statrecords_cmprev (const void *xa, const void *xb)
{
  return -sort_statrecords_cmp (xa, xb);
}


static void
postprocess_statrecords (void)
{
  int i;
  stat_record_t rec;
  int year;
  unsigned int nyr;
  unsigned long euroyr, centyr;

  qsort (statrecords, DIM(statrecords),
         sizeof *statrecords, sort_statrecords_cmp);

  /* Insert the totals per year.  */
  nyr = 0;
  euroyr = centyr = 0;
  year = 0;
  for (i=0; i < DIM (statrecords); i++)
    if ((rec = statrecords + i), rec->year)
      {
        if (rec->year != year)
          {
            nyr = 0;
            euroyr = centyr = 0;
            year = rec->year;
          }
        nyr += rec->n;
        euroyr += rec->euro;
        centyr += rec->cent;

        rec->nyr = nyr;
        rec->euroyr = euroyr;
        rec->centyr = centyr;
      }

  /* The output shall be in reverse chronological order.  */
  qsort (statrecords, DIM(statrecords),
         sizeof *statrecords, sort_statrecords_cmprev);
}


static void
print_output (void)
{
  int i;
  stat_record_t rec;
  unsigned long euro, cent, euroyr, centyr;

  for (i=0; i < DIM (statrecords); i++)
    if ((rec = statrecords + i), rec->year)
      {
        euro = rec->euro;
        cent = rec->cent;
        euro += cent / 100;
        cent %= 100;
        euroyr = rec->euroyr;
        centyr = rec->centyr;
        euroyr += centyr / 100;
        centyr %= 100;
        printf ("%d:%02d::%s:%u::%u:%lu.%02lu:%u:%lu.%02lu:\n",
                rec->year, rec->month, rec->tag, rec->taglnr,
                rec->n, euro, cent,
                rec->nyr, euroyr, centyr);
      }

  if (fflush (stdout) == EOF)
    log_error ("error writing to stdout: %s\n",
               gpg_strerror (gpg_error_from_syserror()));
}
