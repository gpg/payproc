/* payproc-post.c - Do a posting to the payproc database
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

/*


 */



#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"
#include "protocol-io.h"


/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',

    oSeparator  = 500,
    aPing,
    aShutdown,
    aSepa,
    aSepaPreorder,
    aGetPreorder,
    aListPreorder,

    oLive,
    oTest,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, "@Commands:\n "),
  ARGPARSE_c (aPing, "ping",  "Send a ping"),
  ARGPARSE_c (aShutdown,  "shutdown",       "Shutdown server"),
  ARGPARSE_c (aSepa, "sepa",  "Post a SEPA transaction (default)"),
  ARGPARSE_c (aSepaPreorder, "sepa-preorder",  "Insert a SEPA preorder"),
  ARGPARSE_c (aGetPreorder,  "get-preorder",   "Read one preorder"),
  ARGPARSE_c (aListPreorder,  "list-preorder",  "List preorders"),

  ARGPARSE_group (301, "@\nOptions:\n "),
  ARGPARSE_s_n (oVerbose, "verbose",  "verbose diagnostics"),
  ARGPARSE_s_n (oLive, "live",  "enable live mode"),
  ARGPARSE_s_n (oTest, "test",  "enable test mode"),

  ARGPARSE_end ()
};


static struct
{
  int verbose;
  int livemode;

} opt;



/* Local prototypes.  */
static gpg_error_t send_request (const char *command,
                                 keyvalue_t indata, keyvalue_t *outdata);
static void post_sepa (const char *refstring, const char *amountstr);
static void getpreorder (const char *refstring);
static void listpreorder (const char *refstring);
static void sepapreorder (const char *amountstr, const char *name,
                          const char *email, const char *desc);



static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "payproc-post"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 19: p = "Please report bugs to bugs@g10code.com.\n"; break;
    case 1:
    case 40:
      p = ("Usage: payproc-post [options] [command] [args] (-h for help)");
      break;
    case 41:
      p = ("Syntax: payproc-post [options] [--sepa] REF AMOUNT\n"
           "        payproc-post [options] --sepa-preorder AMOUNT\n"
           "Enter a posting to the payproc journal\n");
      break;
    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  fprintf (stderr, "usage: %s [options] %s\n", strusage (11), text);
  exit (2);
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  enum opt_values cmd = 0;
  int live_or_test = 0;

  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("payproc-proc", JNLIB_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  gpgrt_init ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  while (optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case aPing:
        case aShutdown:
        case aSepa:
        case aSepaPreorder:
        case aGetPreorder:
        case aListPreorder:
          if (cmd && cmd != pargs.r_opt)
            {
              log_error ("conflicting commands\n");
              exit (2);
            }
          cmd = pargs.r_opt;
          break;

        case oVerbose: opt.verbose++; break;
        case oLive: opt.livemode = 1; live_or_test = 1; break;
        case oTest: opt.livemode = 0; live_or_test = 1; break;

        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  if (!cmd)
    cmd = aSepa; /* Set default.  */

  if (!live_or_test)
    {
      log_info ("implicitly using --test\n");
    }

  if (cmd == aPing)
    {
      keyvalue_t dict = NULL;

      send_request ("PING", NULL, &dict);
      keyvalue_release (dict);
    }
  else if (cmd == aShutdown)
    {
      keyvalue_t dict = NULL;

      send_request ("SHUTDOWN", NULL, &dict);
      keyvalue_release (dict);
    }
  else if (cmd == aSepa)
    {
      if (argc != 2)
        wrong_args ("--sepa REF AMOUNT");
      ascii_strupr (argv[0]);
      post_sepa (argv[0], argv[1]);
    }
  else if (cmd == aGetPreorder)
    {
      if (argc != 1)
        wrong_args ("--get-preorder REF");
      ascii_strupr (argv[0]);
      getpreorder (argv[0]);
    }
  else if (cmd == aListPreorder)
    {
      if (argc > 1)
        wrong_args ("--list-preorder [NN]");
      listpreorder (argc? argv[0] : NULL);
    }
  else if (cmd == aSepaPreorder)
    {
      if (!argc || argc > 4)
        wrong_args ("--sepa-preorder AMOUNT [NAME [EMAIL [DESC]]]");
      sepapreorder (argv[0],
                    argc > 1? argv[1] : "",
                    argc > 2? argv[2] : "",
                    argc > 3? argv[3] : "");
    }
  else
    usage (1);


  return !!log_get_errorcount (0);
}


/* Connect to the daemon and return an estream for the connected
   socket.  On error returns NULL and sets ERRNO.  */
static estream_t
connect_daemon (const char *name)
{
  int sock;
  struct sockaddr_un addr_un;
  struct sockaddr    *addrp;
  size_t addrlen;
  estream_t fp;

  if (strlen (name)+1 >= sizeof addr_un.sun_path)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  memset (&addr_un, 0, sizeof addr_un);
  addr_un.sun_family = AF_LOCAL;
  strncpy (addr_un.sun_path, name, sizeof (addr_un.sun_path) - 1);
  addr_un.sun_path[sizeof (addr_un.sun_path) - 1] = 0;
  addrlen = SUN_LEN (&addr_un);
  addrp = (struct sockaddr *)&addr_un;

  sock = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (sock == -1)
    return NULL;

  if (connect (sock, addrp, addrlen))
    {
      int saveerr = errno;
      close (sock);
      errno = saveerr;
      return NULL;
    }

  fp = es_fdopen (sock, "r+b");
  if (!fp)
    {
      int saveerr = errno;
      close (sock);
      gpg_err_set_errno (saveerr);
      return NULL;
    }

  return fp;
}


/* Send COMMAND and INDATA to the daemon.  On return OUTDATA is updated with the
   response values.  */
static gpg_error_t
send_request (const char *command, keyvalue_t indata, keyvalue_t *outdata)
{
  gpg_error_t err;
  estream_t fp;
  keyvalue_t kv;
  const char *s;

  fp = connect_daemon (opt.livemode? PAYPROCD_SOCKET_NAME
                       /**/        : PAYPROCD_TEST_SOCKET_NAME);
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("Error connecting payprocd: %s\n", gpg_strerror (err));
      return err;
    }

  es_fprintf (fp, "%s\n", command);
  for (kv = indata; kv; kv = kv->next)
    es_fprintf (fp, "%s: %s\n", kv->name, kv->value);

  es_putc ('\n', fp);

  if (es_ferror (fp) || es_fflush (fp))
    {
      err = gpg_error_from_syserror ();
      log_error ("Error writing to payprocd: %s\n", gpg_strerror (err));
      exit (1);
    }

  err = protocol_read_response (fp, outdata);
  if (err && (s=keyvalue_get (*outdata, "_errdesc")))
    log_error ("Command failed: %s %s%s%s\n",
               gpg_strerror (err), *s == '('?"":"(", s, *s == '('?"":")");
  else if (err)
    log_error ("Error reading from payprocd: %s\n", gpg_strerror (err));

  /* Eat the response for a clean connection shutdown.  */
  while (es_getc (fp) != EOF)
    ;

  es_fclose (fp);

  return err;
}


static void
post_sepa (const char *refstring, const char *amountstr)
{
  gpg_error_t err;
  keyvalue_t input = NULL;
  keyvalue_t output = NULL;
  keyvalue_t kv;

  if (!*amountstr || !convert_amount (amountstr, 2))
    {
      log_error ("Syntax error in amount or value is not positive\n");
      return;
    }

  /* Find reference.  */
  err = keyvalue_put (&input, "Sepa-Ref", refstring);
  if (!err)
    err = keyvalue_put (&input, "Amount", amountstr);
  if (!err)
    err = keyvalue_put (&input, "Currency", "EUR");
  if (err)
    log_fatal ("keyvalue_put failed: %s\n", gpg_strerror (err));

  if (!send_request ("COMMITPREORDER", input, &output))
    {
      for (kv = output; kv; kv = kv->next)
        es_printf ("%s: %s\n", kv->name, kv->value);
    }

  keyvalue_release (input);
  keyvalue_release (output);
}


static void
getpreorder (const char *refstring)
{
  gpg_error_t err;
  keyvalue_t input = NULL;
  keyvalue_t output = NULL;
  keyvalue_t kv;

  /* Find reference.  */
  err = keyvalue_put (&input, "Sepa-Ref", refstring);
  if (err)
    log_fatal ("keyvalue_put failed: %s\n", gpg_strerror (err));

  if (!send_request ("GETPREORDER", input, &output))
    {
      for (kv = output; kv; kv = kv->next)
        es_printf ("%s: %s\n", kv->name, kv->value);
    }

  keyvalue_release (input);
  keyvalue_release (output);
}


static void
listpreorder (const char *refstring)
{
  gpg_error_t err;
  keyvalue_t input = NULL;
  keyvalue_t output = NULL;
  unsigned int n, count;
  char key[30];
  const char *s, *t;
  char **tokens;
  int i;
  int len;

  if (refstring)
    {
      err = keyvalue_put (&input, "Refnn", refstring);
      if (err)
        log_fatal ("keyvalue_put failed: %s\n", gpg_strerror (err));
    }

  if (!send_request ("LISTPREORDER", input, &output))
    {
      count = keyvalue_get_uint (output, "Count");
      es_printf ("Number of records: %u\n", count);
      for (n=0; n < count; n++)
        {
          snprintf (key, sizeof key, "D[%u]", n);
          s = keyvalue_get_string (output, key);
          tokens = strtokenize (*s=='|'? s+1:s, "|");
          if (!tokens)
            log_fatal ("strtokenize failed: %s\n",
                       gpg_strerror (gpg_error_from_syserror ()));
          es_putc ('|', es_stdout);
          for (i=0; (s = tokens[i]); i++)
            {
              if (!*s && !tokens[i+1])
                continue; /* Skip an empty last field.  */
              switch (i)
                {
                case 1: /* Created.   */
                case 2: /* Last Paid - print only date.  */
                  es_printf (" %10.10s |", s );
                  break;
                case 4:
                  t = strchr (s, '.');
                  len = t? (t-s) : strlen (s);
                  es_printf (" %3.*s |", len, s );
                  break;
                case 5: /* Always EUR - don't print.  */
                  break;
                case 6: /* Don't print the description.  */
                  break;
                case 7: /* Email */
                  es_printf (" %-20s |", s );
                  break;
                default:
                  es_printf (" %s |", s );
                  break;
                }
            }
          es_putc ('\n', es_stdout);
          xfree (tokens);
        }
    }

  keyvalue_release (input);
  keyvalue_release (output);
}


static void
sepapreorder (const char *amountstr, const char *name,
              const char *email, const char *desc)
{
  gpg_error_t err;
  keyvalue_t input = NULL;
  keyvalue_t output = NULL;
  keyvalue_t kv;

  if (!*amountstr || !convert_amount (amountstr, 2))
    {
      log_error ("Syntax error in amount or value is not positive\n");
      return;
    }

  /* Find reference.  */
  err = keyvalue_put (&input, "Amount", amountstr);
  if (!err && *name)
    err = keyvalue_put (&input, "Meta[Name]", name);
  if (!err && *email)
    err = keyvalue_put (&input, "Email", email);
  if (!err && *desc)
    err = keyvalue_put (&input, "Desc", desc);
  if (err)
    log_fatal ("keyvalue_put failed: %s\n", gpg_strerror (err));

  if (!send_request ("SEPAPREORDER", input, &output))
    {
      for (kv = output; kv; kv = kv->next)
        es_printf ("%s: %s\n", kv->name, kv->value);
    }

  keyvalue_release (input);
  keyvalue_release (output);
}
