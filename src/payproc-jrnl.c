/* payproc-jrnl.c - Payproc journal tool
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
#include <gpg-error.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"
#include "estream.h"


/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',
    oIgnoreCase = 'i',
    oField      = 'F',
    oSelect     = 'S',

    aCount      = 500,
    aPrint,

    oHTML,
    oSeparator,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, "@Commands:\n "),

  ARGPARSE_c (aCount, "count", "count selected records"),
  ARGPARSE_c (aPrint, "print", "print fields from selected records"),

  ARGPARSE_group (301, "@\nOptions:\n "),

  ARGPARSE_s_n (oVerbose,"verbose",  "verbose diagnostics"),
  ARGPARSE_s_n (oHTML,   "html",     "print for use with HTML"),
  ARGPARSE_s_n (oIgnoreCase, "ignore-case", "ignore case in record matching"),
  ARGPARSE_s_s (oSeparator, "separator", "|CHAR|use CHAR as output separator"),
  ARGPARSE_s_s (oField,  "field",    "|NAME|output field NAME"),
  ARGPARSE_s_s (oSelect, "select",   "|EXPR|output records matching EXPR"),

  ARGPARSE_end ()
};

/* List of the journal field names.  */
static char *jrnl_field_names[] =
  {
    "_lnr", /* virtual field.  */
    "date", "type", "live", "currency", "amount",
    "desc", "mail", "meta", "last4", "service", "account",
    "chargeid", "txid", "rtxid"
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


/* Definition for field names.  */
typedef struct outfield_s
{
  struct outfield_s *next;
  int meta;
  unsigned int fnr;
  char name[1];
} *outfield_t;


/* Command line options.  */
static struct
{
  int verbose;
  int html;
  int separator;
  int ignorecase;
  outfield_t outfields;
  selectexpr_t selectexpr;
} opt;


/* The general action - one of the opt_values.  */
static int command;

/* Total number of selected records so far.  */
static unsigned int recordcount;


/* Local prototypes.  */
static const char *get_fieldname (int fnr);
static int parse_fieldname (char *name, int *r_meta, unsigned int *r_fnr);
static selectexpr_t parse_selectexpr (const char *expr);
static void one_file (const char *fname);



static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "payproc-jrnl"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 19: p = "Please report bugs to bugs@g10code.com.\n"; break;
    case 1:
    case 40: p = "Usage: payproc-jrnl [options] FILES (-h for help)"; break;
    case 41: p = ("Syntax: payproc-jrnl [options]\n"
                  "Payproc journal tool\n"); break;
    default: p = NULL; break;
    }
  return p;
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  outfield_t of, of2;
  selectexpr_t se, se2;

  opt.separator = ':';

  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("payproc-jrnl", JNLIB_LOG_WITH_PREFIX);

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
        case aCount:
        case aPrint:
          command = pargs.r_opt;
          break;

        case oVerbose:  opt.verbose++; break;
        case oHTML: opt.html = 1; break;
        case oIgnoreCase: opt.ignorecase = 1; break;
        case oSeparator:
          if (strlen (pargs.r.ret_str) > 1)
            log_error ("--separator takes only a single character\n");
          else
            opt.separator = *pargs.r.ret_str;
          break;
        case oField:
	  of = xmalloc (sizeof *of + strlen (pargs.r.ret_str));
	  strcpy (of->name, pargs.r.ret_str);
	  of->next = NULL;
          of->meta = 0;
          of->fnr = 0;
          if (parse_fieldname (of->name, &of->meta, &of->fnr))
            ;
	  else if (!(of2 = opt.outfields))
	    opt.outfields = of;
	  else
	    {
	      for (; of2->next; of2 = of2->next)
		;
	      of2->next = of;
	    }
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


        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);
  if (!command)
    {
      log_info ("no command given - assuming '--count'\n");
      command = aCount;
    }

  /* Debug output.  */
  if (opt.outfields && opt.verbose > 1)
    {
      log_info ("--- Begin output fields ---\n");
      for (of = opt.outfields; of; of = of->next)
        {
          if (of->meta)
            log_info ("meta '%s'\n", of->name);
          else
            log_info (" %3d '%s'\n", of->fnr, get_fieldname (of->fnr));
        }
      log_info ("--- End output fields ---\n");
    }
  if (opt.selectexpr && opt.verbose > 1)
    {
      log_info ("--- Begin selectors ---\n");
      for (se=opt.selectexpr; se; se = se->next)
        log_info ("*(%s) %s '%s'\n",
                  se->name,
                  se->op == SELECT_SAME?    "= ":
                  se->op == SELECT_NOTSAME? "<>":
                  se->op == SELECT_SUB?     "=~":
                  se->op == SELECT_NOTSUB?  "!~":
                  se->op == SELECT_EMPTY?   "-z":
                  se->op == SELECT_NOTEMPTY?"-n":
                  se->op == SELECT_EQ?      "==":
                  se->op == SELECT_NE?      "!=":
                  se->op == SELECT_LT?      "< ":
                  se->op == SELECT_LE?      "<=":
                  se->op == SELECT_GT?      "> ":
                  se->op == SELECT_GE?      ">=":"[oops]",
                  se->value);
      log_info ("--- End selectors ---\n");
    }

  /* Process all files.  */
  for (; argc; argc--, argv++)
    {
      one_file (*argv);
    }

  /* Print totals.  */
  if (command == aCount)
    es_printf ("%u\n", recordcount);

  return !!log_get_errorcount (0);
}


/* Return the name of the field with FNR.  */
static const char *
get_fieldname (int fnr)
{
  if (fnr < 0 || fnr >= DIM(jrnl_field_names))
    return "?";
  return jrnl_field_names[fnr];
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


/* Print a string.  */
static void
print_string (const char *string)
{
  if (opt.html)
    {
      const char *s;
      char *raw;

      raw = percent_unescape (string, ' ');
      if (!raw)
        log_fatal ("percent_unescape failed: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));

      for (s = raw; *s; s++)
        {
          if (*s == opt.separator)
            es_printf ("&#%d;", opt.separator);
          else if (*s == '<')
            es_fputs ("&lt;", es_stdout);
          else if (*s == '>')
            es_fputs ("&gt;", es_stdout);
          else if (*s == '&')
            es_fputs ("&amp;", es_stdout);
          else if (*s == '\n')
            es_fputs ("<br/>", es_stdout);
          else if (*s == '\r')
            ;
          else
            es_putc (*s, es_stdout);
        }

      xfree (raw);
    }
  else
    es_fputs (string, es_stdout);
}


/* Print a meta subfield with NAME.  BUFFER holds the name/value pair
   of that subfield.  Return true if NAME matches.  */
static int
print_meta_sub (char *buffer, const char *name)
{
  char *p;

  /* In theory name could be escaped but we neglect that because this
     does not make any sense.  */
  p = strchr (buffer, '=');
  if (!p)
    return 0; /* No name/value.  */
  *p = 0;
  if (strcmp (buffer, name))
    {
      *p = '=';
      return 0; /* Does not match.  */
    }
  *p++ = '=';

  /* We can keep the percent escaping.  */
  print_string (p);
  return 1;   /* Found.  */
}


/* Print the meta subfield NAME from BUFFER which holds the entire
   meta field. */
static void
print_meta (char *buffer, const char *name)
{
  char *p;

  do
    {
      p = strchr (buffer, '&');
      if (p)
        *p = 0;
      if (print_meta_sub (buffer, name))
        {
          if (p)
            *p = '&';
          return;
        }
      if (p)
        *p++ = '&';
      buffer = p;
    }
  while (buffer);
}


/* Process one journal line.  LINE has no trailing LF.  The function
   may change LINE.  */
static int
one_line (const char *fname, unsigned int lnr, char *line)
{
  char *field[12];
  int nfields = 0;

  /* Parse into fields.  */
  while (line && nfields < DIM(field))
    {
      field[nfields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }
  if (nfields < DIM(field))
    {
      log_error ("%s:%u: not enough fields - not a Payproc journal?\n",
                 fname, lnr);
      return -1;
    }

  if (opt.selectexpr && !select_record_p (field, nfields, lnr))
    return 0; /* Not selected.  */


  recordcount++;

  /* Process.  */
  if (command == aCount)
    ;
  else if (command == aPrint)
    {
      outfield_t of;
      int i;

      if (opt.outfields)
        {
          for (of = opt.outfields; of; of = of->next)
            {
              if (of->meta)
                {
                  if (nfields > 7)
                    print_meta (field[7], of->name);
                }
              else if (!of->fnr)
                es_printf ("%u", lnr);
              else if (of->fnr-1 < nfields)
                print_string (field[of->fnr-1]);

              if (of->next)
                es_putc (opt.separator, es_stdout);
            }
        }
      else
        {
          for (i=0; i < nfields;)
            {
              print_string (field[i]);
              if (++i < nfields)
                es_putc (opt.separator, es_stdout);
            }
        }
      es_putc ('\n', es_stdout);
    }

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
      if (nread && one_line (fname, lnr, buffer))
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
