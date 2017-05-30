/* ppsepaqr - Create a SEPA QR code
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


#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>
#include <assert.h>
#include <ctype.h>
#include <qrencode.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"

/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',

    oDebug = 500,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, "@\nOptions:\n "),

  ARGPARSE_s_n (oVerbose,"verbose",  "verbose diagnostics"),

  ARGPARSE_end ()
};


/* Gobal options.  */
static struct
{
  int verbose;
} opt;




/* Local prototypes.  */
static char *format_data (const char *iban, const char *name,
                          const char *amount, const char *text);
static void encode (const char *text, estream_t fp);




static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "ppsepaqr"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 19: p = "Please report bugs to https://bugs.gnupg.org.\n"; break;
    case 1:
    case 40: p =
        "Usage: ppsepaqr [options] IBAN NAME AMOUNT TEXT  (-h for help)";
      break;
    case 41: p =
        "Syntax: ppsepaqr [options] IBAN NAME AMOUNT TEXT\n"
        "Print an SVG with the QR code for a SEPA transaction\n";
      break;
    default: p = NULL; break;
    }
  return p;
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  char *data;

  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("ppsepaqr", JNLIB_LOG_WITH_PREFIX);

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
        case oVerbose:  opt.verbose++; break;

        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (log_get_errorcount (0))
    exit (2);

  if (argc != 4)
    usage (1);

  data = format_data (argv[0], argv[1], argv[2], argv[3]);
  if (data)
    {
      encode (data, es_stdout);
      if (es_ferror (es_stdout) || es_fflush (es_stdout))
        log_error ("error writing to stdout: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));

      xfree (data);
    }

  return !!log_get_errorcount (0);
}


/* Create a string with the data accroding to "EPC069-12v2.1 Quick
 * Response Code - Guidelines to Enable the Data Capture for the
 * Initiation of a SCT".  Returns a malloced string or NULL on
 * error. In the error case a diagnositc has been printed.  */
static char *
format_data (const char *iban, const char *name, const char *amount,
             const char *text)
{
  char *string;
  int anyerr = 0;
  unsigned int cents;
  char *xamount;
  char *xtext;
  char *p;

  /* Check various things.  */
  if (strlen (iban) < 8 /* arbitrary value - what is the right one?*/
      || strlen (iban) > 34
      || strchr (iban, '\n') || strchr (iban, '\r'))
    {
      log_error ("invalid IBAN given");
      anyerr++;
    }

  if (!*name || strlen (name) > 70
      || strchr (name, '\n') || strchr (name, '\r'))
    {
      log_error ("invalid or too long NAME given\n");
      anyerr++;
    }

  cents = convert_amount (amount, 2);
  if (!cents)
    {
      log_error ("invalid AMOUNT given\n");
      anyerr++;
    }
  xamount = reconvert_amount (cents, 2);
  if (!xamount)
    {
      log_error ("error formatting amount: %s\n",
                 gpg_strerror (gpg_error_from_syserror ()));
      return NULL;
    }

  xtext = xstrdup (text);
  for (p=xtext; *p; p++)
    if (*p == '\n' || *p == '\r')
      *p = ' ';
  trim_spaces (xtext);
  if (!*xtext)
    {
      log_error ("empty TEXT is not allowed\n");
      anyerr++;
    }
  if (strlen (xtext) > 140)
    {
      /* FIXME: This may invalidate UTF-8 chars.  */
      xtext[140] = 0;
      log_info ("TEXT truncated to 140 octets\n");
    }

  if (anyerr)
    string = NULL;
  else
    {
      string = strconcat ("BCD\n"
                          "002\n"
                          "1\n"
                          "SCT\n"
                          "\n",  /* BIC is not anymore used.  */
                          name, "\n",
                          iban, "\n",
                          "EUR", xamount, "\n",
                          "\n"         /* Purpose */
                          "\n",        /* Remittance info (structured) */
                          xtext, "\n", /* Remittance info (unstructured) */
                          "",           /* Information.  */
                          NULL );
      if (!string)
        log_error ("strconcat failed: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
    }

  es_free (xamount);
  xfree (xtext);
  return string;
}


/* Encode to QR and render as SVG to FP  */
static void
encode (const char *text, estream_t fp)
{
  QRcode *code;
  unsigned int symwidth;
  float realwidth;
  const unsigned char *row;
  unsigned int x, y, width, x2;

  code = QRcode_encodeString (text, 0, QR_ECLEVEL_M, QR_MODE_8, 1);
  if (!code)
    {
      log_error ("QR encoding failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror ()));
      return;
    }

#define SVG_MARGIN 4
#define SVG_PIXELS 3
#define SVG_DPI 72

  symwidth = code->width + SVG_MARGIN * 2;
  realwidth = (symwidth * SVG_PIXELS) / (SVG_DPI * (100.0/2.54) / 100.0);

  es_fprintf (fp,
              "<svg width=\"%0.2fcm\" height=\"%0.2fcm\""
              " viewBox=\"0 0 %d %d\"\n"
              "     preserveAspectRatio=\"none\" version=\"1.1\"\n"
              "     shape-rendering=\"crispEdges\"\n"
              "     xmlns=\"http://www.w3.org/2000/svg\">\n"
              "  <g id=\"QRcode\">\n"
              "    <rect x=\"0\" y=\"0\" width=\"%d\" height=\"%d\""
              " fill=\"#ffffff\"/>\n"
              "    <g id=\"Pattern\">\n",
              realwidth, realwidth,
              symwidth,  symwidth,
              symwidth,  symwidth );

  for (y = 0; y < code->width; y++)
    {
      row = code->data + (y * code->width);
      for (x = 0; x < code->width; x++)
        {
          for (width=0, x2=x; (row[x2] & 1) && x2 < code->width; x2++, width++)
            ;
          if (width)
            {
              es_fprintf (fp,
                          "      <rect x=\"%d\" y=\"%d\""
                          " width=\"%d\" height=\"1\""
                          " fill=\"#000000\"/>\n",
                          SVG_MARGIN + x, SVG_MARGIN + y, width);
              x += width - 1;
            }
	}
    }

  es_fputs ("    </g>\n"
            "  </g>\n"
            "</svg>\n",
            fp);

  QRcode_free (code);
}
