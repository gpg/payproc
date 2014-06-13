/* ppipnhd.c - PayPal IPN Handler CGI.
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

/* This is a CGI acting as a proxy for IPN messages from PayPal.  It
   merely reads the request, passes it on to payprocd, and sends back
   a 200 HTTP response.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define PGM "ppipnhd"
#define MAX_REQUEST (64*1024)


/* Allow building standalone.  */
#ifndef PAYPROCD_SOCKET_NAME
#define PAYPROCD_SOCKET_NAME "/var/run/payproc/dameon"
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "payproc"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION __DATE__
#endif


static void
print_status (int n, const char *text)
{
  printf ("Status: %d %s\r\n", n, text);
}


static void
exit_status (int n, const char *text)
{
  print_status (n, text);
  fputs ("Content-Type: text/plain\r\n\r\n", stdout);
  exit (0);
}


/* Connect to the daemon and return stdio stream for the connected a
   socket.  On error returns NULL and sets ERRNO.  */
static FILE *
connect_daemon (const char *name)
{
  int sock;
  struct sockaddr_un addr_un;
  struct sockaddr    *addrp;
  size_t addrlen;
  FILE *fp;

  if (strlen (name)+1 >= sizeof addr_un.sun_path)
    {
      errno = EINVAL;
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

  fp = fdopen (sock, "r+b");
  if (!fp)
    {
      int saveerr = errno;
      close (sock);
      errno = saveerr;
      return NULL;
    }

  return fp;
}


/* Send the payload to the daemon.  Does not return an error.  */
static void
send_to_daemon (const char *buffer)
{
  FILE *fp;
  int n, c;

  fp = connect_daemon (PAYPROCD_SOCKET_NAME);
  if (!fp)
    exit_status (500, "Error connecting payprocd");

  fputs ("PPIPNHD\nRequest: ", fp);
  n = 9;
  while ((c = *buffer++))
    {
      if (n==1024)
        {
          putc ('\n', fp);
          putc (' ', fp);
          n = 0;
        }
      putc (c, fp);
      n++;
    }
  putc ('\n', fp);
  putc ('\n', fp);
  if (ferror (fp))
    exit_status (500, "Error writing to payprocd");

  /* Payproc daemon does not return anything real but in case of an
     error in this code we check whether the response is OK and not ERR.  */
  c = fgetc (fp);
  if (c != 'O')
    exit_status (500, "Error talking to payprocd");
  /* Eat the response for a clean connection shutdown.  */
  while (getc (fp) != EOF)
    ;

  fclose (fp);
}


int
main (int argc, char **argv)
{
  const char *request_method = getenv("REQUEST_METHOD");
  const char *content_length = getenv("CONTENT_LENGTH");
  const char *content_type   = getenv("CONTENT_TYPE");
  unsigned long length, n;
  char *buffer;

  /* Allow the usual "--version" option only if run outside of the COI
     environment.  */
  if (argc > 1 && !strcmp (argv[1], "--version") && !request_method)
    {
      fputs (PGM " (" PACKAGE_NAME ") " PACKAGE_VERSION "\n", stdout);
      return 0;
    }

  if (!request_method || strcmp (request_method, "POST"))
    exit_status (501, "Only POST allowed");

  length = content_length? strtoul (content_length, NULL, 10) : 0;
  if (!length)
    exit_status (411, "Content-Length missing");
  if (length >= MAX_REQUEST)
    exit_status (413, "Payload too large");

  if (!content_type || !*content_type)
    exit_status (400, "Content-type missing");

  buffer = malloc (length+1);
  if (!buffer)
    exit_status (503, "Service currently unavailable");

  if (fread (buffer, length, 1, stdin) != 1)
    exit_status (400, feof (stdin)? "Payload shorter than indicated"
                 /*            */ : "Error reading payload");
  buffer[length] = 0; /* Make it a string.  */
  for (n=0; n < length; n++)
    {
      if (!buffer[n])
        exit_status (400, "Binary data in payload not allowed");
      if (strchr (" \t\r\n", buffer[n]))
        exit_status (400, "Whitespaces in payload not allowed");
    }


  send_to_daemon (buffer);
  free (buffer);

  print_status (200, "OK");
  fputs ("Content-Type: text/plain\r\n\r\n", stdout);
  return 0;
}
