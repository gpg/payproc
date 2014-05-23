/* payprocd.c - Payproc daemon
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <gpg-error.h>
#include <npth.h>
#include <gcrypt.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"
#include "estream.h"
#include "connection.h"
#include "tlssupport.h"
#include "cred.h"
#include "journal.h"
#include "session.h"
#include "payprocd.h"


/* The name of the socket handling commands.  */
#define SOCKET_NAME "/var/run/payproc/daemon"

/* The interval in seconds to check whether to do housekeeping.  */
#define TIMERTICK_INTERVAL  30

/* The interval in seconds to run the housekeeping thread.  */
#define HOUSEKEEPING_INTERVAL  (120)

/* Flag indicating that the socket shall shall be removed by
   cleanup.  */
static int remove_socket_flag;

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Number of active connections.  */
static int active_connections;

/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',
    oAllowUID   = 'U',
    oAllowGID   = 'G',

    oLogFile   = 500,
    oNoDetach,
    oJournal,
    oStripeKey,
    oLive,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, "@Options:\n "),

  ARGPARSE_s_n (oVerbose,  "verbose",   "verbose"),
  ARGPARSE_s_n (oNoDetach, "no-detach", "do not detach from the console"),
  ARGPARSE_s_s (oLogFile,  "log-file",  "|FILE|write log output to FILE"),
  ARGPARSE_s_s (oAllowUID, "allow-uid", "|N|allow access from uid N"),
  ARGPARSE_s_s (oAllowGID, "allow-gid", "|N|allow access from gid N"),
  ARGPARSE_s_s (oJournal,  "journal",   "|FILE|write the journal to FILE"),
  ARGPARSE_s_s (oStripeKey,
                "stripe-key", "|FILE|read key for Stripe account from FILE"),
  ARGPARSE_s_n (oLive, "live",  "enable live mode"),

  ARGPARSE_end ()
};




/* Local prototypes.  */
static void cleanup (void);
static void launch_server (const char *logfile);
static void server_loop (int fd);
static void handle_tick (void);
static void handle_signal (int signo);
static void *connection_thread (void *arg);




static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "payprocd"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 19: p = "Please report bugs to bugs@g10code.com.\n"; break;
    case 1:
    case 40: p = "Usage: payprocd [options] (-h for help)"; break;
    case 41: p = ("Syntax: payprocd [options]\n"
                  "Start the payment processing daemon\n"); break;
    default: p = NULL; break;
    }
  return p;
}

/* Set the Stripe secret key from file FNAME.  */
static void
set_stripe_key (const char *fname)
{
  FILE *fp;
  char buf[128];

  fp = fopen (fname, "r");
  if (!fp)
    log_error ("error opening key file '%s': %s\n", fname, strerror (errno));
  else
    {
      if (!fgets (buf, sizeof buf, fp))
        log_error ("error reading key from '%s': %s\n",
                   fname, strerror (errno));
      else
        {
          trim_spaces (buf);
          if (strncmp (buf, "sk_test_", 8) && strncmp (buf, "sk_live_", 8))
            log_error ("file '%s' seems not to carry a Stripe secret key\n",
                       fname);
          else
            {
              xfree (opt.stripe_secret_key);
              opt.stripe_secret_key = xstrdup (buf);
            }
        }
      fclose (fp);
    }
}


int
main (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  const char *logfile = NULL;

  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("payprocd", JNLIB_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  es_init ();
  /* Access the standard estreams as early as possible.  If we don't
     do this the original stdio streams may have been closed when
     _es_get_std_stream is first use and in turn it would connect to
     the bit bucket.  */
  {
    int i;
    for (i=0; i < 3; i++)
      (void)_es_get_std_stream (i);
  }

  npth_init ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  /* Check that Libgcrypt is suitable.  */
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal ("%s is too old (need %s, have %s)\n", "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  /* Initialze processing subsystems.  */
  init_tls_subsystem ();

  /* Parse the command line. */
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
  while (optfile_parse (NULL, NULL, NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose:  opt.verbose++; break;
        case oNoDetach: opt.nodetach = 1; break;
        case oLogFile:  logfile = pargs.r.ret_str; break;
        case oJournal:  jrnl_set_file (pargs.r.ret_str); break;
        case oAllowUID: /*FIXME*/ break;
        case oAllowGID: /*FIXME*/ break;
        case oStripeKey: set_stripe_key (pargs.r.ret_str); break;
        case oLive: opt.livemode = 1; break;

        default: pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (opt.livemode && (!opt.stripe_secret_key
                       || strncmp (opt.stripe_secret_key, "sk_live_", 8)))
    log_error ("live mode requested but no live key given\n");
  else if (!opt.livemode
           && opt.stripe_secret_key
           && !strncmp (opt.stripe_secret_key, "sk_live_", 8))
    log_error ("test mode requested but live key given\n");

  if (log_get_errorcount (0))
    exit (2);

  if (opt.livemode)
    log_fatal ("live mode rejected - we need more testing first\n");

  /* Start the server.  */
  launch_server (logfile);

  return 0;
}


/* Cleanup handler - usually called via atexit.  */
static void
cleanup (void)
{
  static int done;

  if (done)
    return;
  done = 1;

  if (remove_socket_flag)
    remove (SOCKET_NAME);
}


/* Check whether a daemon is already running on the socket NAME.  */
static int
already_running_p (const char *name)
{
  struct sockaddr_un *addr;
  socklen_t len;
  int rc;
  int fd;
  estream_t stream;
  char buffer[256];

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_error ("error creating socket: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      exit (2);
    }

  addr = xcalloc (1, sizeof *addr);
  addr->sun_family = AF_UNIX;
  if (strlen (name) + 1 >= sizeof (addr->sun_path))
    {
      log_error ("socket name '%s' is too long\n", name);
      exit (2);
    }
  strcpy (addr->sun_path, name);
  len = SUN_LEN (addr);

  rc = connect (fd, (struct sockaddr *)addr, len);
  if (rc == -1)
    {
      close (fd);
      return 0; /* Probably not running.  Well, as long as the
                   permissions are suitable.  */
    }

  /* Also do an alive check for diagnositc reasons.  */
  stream = es_fdopen (fd, "r+b,samethread");
  if (!stream)
    {
      log_error ("failed to fdopen connected socket: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      close (fd);
      return 1;  /* Assume it is running.  */
    }
  es_fputs ("PING\n\n", stream);
  es_fflush (stream);
  if (!es_fgets (buffer, sizeof buffer, stream))
    {
      log_error ("failed to read PING response from '%s': %s\n", name,
                 gpg_strerror (gpg_error_from_syserror()));
    }
  else if (!has_leading_keyword (buffer, "OK"))
    {
      log_error ("PING command on '%s' failed *%s)\n", name, buffer);
    }

  es_fclose (stream);

  return 1;  /* Assume the server is running.  */
}


/* Create a Unix domain socket with NAME.  Returns the file descriptor
   or terminates the process in case of an error.  */
static int
create_socket (char *name)
{
  struct sockaddr_un *serv_addr;
  socklen_t len;
  int fd;
  int rc;

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    {
      log_error ("error creating socket: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      exit (2);
    }

  serv_addr = xmalloc (sizeof (*serv_addr));
  memset (serv_addr, 0, sizeof *serv_addr);
  serv_addr->sun_family = AF_UNIX;
  if (strlen (name) + 1 >= sizeof (serv_addr->sun_path))
    {
      log_error ("socket name '%s' is too long\n", name);
      exit (2);
    }
  strcpy (serv_addr->sun_path, name);
  len = SUN_LEN (serv_addr);
  rc = bind (fd, (struct sockaddr*) serv_addr, len);
  if (rc == -1 && errno == EADDRINUSE)
    {
      if (already_running_p (name))
        {
          log_error ("a payprocd process is already running - "
                     "not starting a new one\n");
          close (fd);
          exit (2);
        }
      /* Remove a stale socket file and try again.  */
      remove (name);
      rc = bind (fd, (struct sockaddr*) serv_addr, len);
    }
  if (rc == -1)
    {
      log_error ("error binding socket to '%s': %s\n",
		 serv_addr->sun_path,
                 gpg_strerror (gpg_error_from_syserror()));

      close (fd);
      exit (2);
    }

  if (listen (fd, 5 ) == -1)
    {
      log_error ("listen call failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      close (fd);
      exit (2);
    }

  if (opt.verbose)
    log_info ("listening on socket '%s'\n", serv_addr->sun_path);

  return fd;
}


/* Fire up the server.  */
static void
launch_server (const char *logfile)
{
  int fd;
  pid_t pid;

  fd = create_socket (SOCKET_NAME);
  fflush (NULL);
  pid = fork ();
  if (pid == (pid_t)-1)
    {
      log_fatal ("fork failed: %s\n", strerror (errno) );
      exit (1);
    }
  else if (pid)
    { /* We are the parent */

      remove_socket_flag = 0; /* Now owned by the child.  */
      close (fd);
      exit (0);
    } /* End parent */

  /*
    This is the child
  */

  remove_socket_flag = 1;

  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (JNLIB_LOG_WITH_PREFIX
                             |JNLIB_LOG_WITH_TIME
                             |JNLIB_LOG_WITH_PID));
    }
  else
    log_set_prefix (NULL, (JNLIB_LOG_WITH_PREFIX
                           |JNLIB_LOG_WITH_PID));

  /* Detach from tty and put process into a new session */
  if (!opt.nodetach )
    {
      int i;
      unsigned int oldflags;

      /* Close stdin, stdout and stderr unless it is the log stream */
      for (i=0; i <= 2; i++)
        {
          if (!log_test_fd (i) && i != fd )
            {
              if ( ! close (i)
                   && open ("/dev/null", i? O_WRONLY : O_RDONLY) == -1)
                {
                  log_error ("failed to open '%s': %s\n",
                             "/dev/null", strerror (errno));
                  cleanup ();
                  exit (1);
                }
            }
        }
      if (setsid() == -1)
        {
          log_error ("setsid() failed: %s\n", strerror(errno) );
          cleanup ();
          exit (1);
        }

      log_get_prefix (&oldflags);
      log_set_prefix (NULL, oldflags | JNLIB_LOG_RUN_DETACHED);
    }

  if (chdir("/"))
    {
      log_error ("chdir to / failed: %s\n", strerror (errno));
      exit (1);
    }

  {
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction (SIGPIPE, &sa, NULL);
  }

  log_info ("payprocd %s started\n", PACKAGE_VERSION);
  jrnl_store_sys_record ("payprocd "PACKAGE_VERSION" started");
  server_loop (fd);
  close (fd);
}


/* Main loop: The loops waits for connection requests and spawn a
   working thread after accepting the connection.  */
static void
server_loop (int listen_fd)
{
  gpg_error_t err;
  npth_attr_t tattr;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  int fd;
  int nfd;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;

  ret = npth_attr_init (&tattr);
  if (ret)
    log_fatal ("error allocating thread attributes: %s\n",
	       strerror (ret));
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();

  FD_ZERO (&fdset);
  FD_SET (listen_fd, &fdset);
  nfd = listen_fd;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  for (;;)
    {
      /* Shutdown test.  */
      if (shutdown_pending)
        {
          if (!active_connections)
            break; /* ready */

          /* Do not accept new connections but keep on running the
             loop to cope with the timer events.  */
          FD_ZERO (&fdset);
	}

      read_fdset = fdset;

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
        {
          /* Timeout.  */
          handle_tick ();
          npth_clock_gettime (&abstime);
          abstime.tv_sec += TIMERTICK_INTERVAL;
        }
      npth_timersub (&abstime, &curtime, &timeout);

      ret = npth_pselect (nfd+1, &read_fdset, NULL, NULL, &timeout,
                          npth_sigev_sigmask ());
      err = (ret == -1)? gpg_error_from_syserror () : 0;

      {
        int signo;
        while (npth_sigev_get_pending (&signo))
          handle_signal (signo);
      }

      if (err && gpg_err_code (err) != GPG_ERR_EINTR)
	{
          log_error ("npth_pselect failed: %s - waiting 1s\n",
                     gpg_strerror (err));
          npth_sleep (1);
          continue;
	}
      if (ret <= 0)
        {
          /* Interrupt or timeout.  To be handled when computing the
             next timeout.  */
          continue;
        }

      if (!shutdown_pending && FD_ISSET (listen_fd, &read_fdset))
	{
          conn_t conn;

          plen = sizeof paddr;
	  fd = npth_accept (listen_fd, (struct sockaddr *)&paddr, &plen);
	  if (fd == -1)
	    {
              err = gpg_error_from_syserror ();
	      log_error ("accept failed: %s\n", gpg_strerror (err));
	    }
          else if (!(conn = new_connection_obj ()))
            {
              err = gpg_error_from_syserror ();
              log_error ("error allocating connection object: %s\n",
                         gpg_strerror (err) );
              close (fd);
              fd = -1;
            }
          else
            {
	      npth_t thread;

              init_connection_obj (conn, fd);
              fd = -1; /* Now owned by CONN.  */
	      ret = npth_create (&thread, &tattr, connection_thread, conn);
              if (ret)
                {
                  err = gpg_error_from_errno (ret);
                  log_error ("error spawning connection handler: %s\n",
			     gpg_strerror (err));
                  release_connection_obj (conn);
                }
            }
	}
    }

  jrnl_store_sys_record ("payprocd "PACKAGE_VERSION" stopped");
  log_info ("payprocd %s stopped\n", PACKAGE_VERSION);
  cleanup ();
  npth_attr_destroy (&tattr);
}


#if JNLIB_GCC_HAVE_PUSH_PRAGMA
# pragma GCC push_options
# pragma GCC optimize ("no-strict-overflow")
#endif
static int
time_for_housekeeping_p (time_t now)
{
  static time_t last_housekeeping;

  if (!last_housekeeping)
    last_housekeeping = now;

  if (last_housekeeping + HOUSEKEEPING_INTERVAL <= now
      || last_housekeeping > now /*(be prepared for y2038)*/)
    {
      last_housekeeping = now;
      return 1;
    }
  return 0;
}
#if JNLIB_GCC_HAVE_PUSH_PRAGMA
# pragma GCC pop_options
#endif


/* Thread to do the housekeeping.  */
static void *
housekeeping_thread (void *arg)
{
  static int sentinel;

  (void)arg;

  if (sentinel)
    {
      log_info ("only one cleaning person at a time please\n");
      return NULL;
    }
  sentinel++;
  if (opt.verbose)
    log_info ("starting housekeeping\n");

  session_housekeeping ();

  if (opt.verbose)
    log_info ("finished with housekeeping\n");
  sentinel--;
  return NULL;

}


/* This is the worker for the ticker.  It is called every few seconds
   and may only do fast operations. */
static void
handle_tick (void)
{
  if (time_for_housekeeping_p (time (NULL)))
    {
      npth_t thread;
      npth_attr_t tattr;
      int rc;

      rc = npth_attr_init (&tattr);
      if (rc)
        log_error ("error preparing housekeeping thread: %s\n", strerror (rc));
      else
        {
          npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
          rc = npth_create (&thread, &tattr, housekeeping_thread, NULL);
          if (rc)
            log_error ("error spawning housekeeping thread: %s\n",
                       strerror (rc));
          npth_attr_destroy (&tattr);
        }
    }
}


/* The signal handler for payprocd.  It is expected to be run in its
   own thread and not in the context of a signal handler.  */
static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - nothing to do right now\n");
      break;

    case SIGUSR2:
      log_info ("SIGUSR2 received - nothing to do right now\n");
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %d open connections\n",
		  active_connections);
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          jrnl_store_sys_record ("payprocd "PACKAGE_VERSION
                                 " stopped (forced)");
          log_info ("payprocd %s stopped\n", PACKAGE_VERSION);
          cleanup ();
          exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      jrnl_store_sys_record ("payprocd "PACKAGE_VERSION" stopped (SIGINT)");
      log_info( "payprocd %s stopped\n", PACKAGE_VERSION);
      cleanup ();
      exit (0);
      break;

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}


/* A connection thread's main function.  */
static void *
connection_thread (void *arg)
{
  conn_t conn = arg;
  pid_t pid;
  uid_t uid;
  gid_t gid;

  if (credentials_from_socket (fd_from_connection_obj (conn), &pid, &uid, &gid))
    {
      log_error ("connection %u: credentials missing - closing\n",
                 id_from_connection_obj (conn));
      goto leave;
    }

  if (opt.verbose)
    log_info ("connection %u: started - pid=%u uid=%u gid=%u\n",
              id_from_connection_obj (conn),
              (unsigned int)pid, (unsigned int)uid, (unsigned int)gid);

  connection_handler (conn);

  if (opt.verbose)
    log_info ("connection %u: terminated\n", id_from_connection_obj (conn));

 leave:
  release_connection_obj (conn);
  return NULL;
}
