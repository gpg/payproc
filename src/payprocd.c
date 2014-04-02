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

#include "util.h"
#include "logging.h"
#include "estream.h"
#include "connection.h"
#include "tlssupport.h"
#include "payprocd.h"


/* The name of the socket handling commands.  */
#define SOCKET_NAME "/var/run/payproc/daemon"

/* The interval in seconds for the housekeeping thread.  */
#define TIMERTICK_INTERVAL  60



/* Flag indicating that the socket shall shall be removed by
   cleanup.  */
static int remove_socket_flag;

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* Number of active connections.  */
static int active_connections;




/* Local prototypes.  */
static void cleanup (void);
static void launch_server (void);
static void server_loop (int fd);
static void handle_signal (int signo);
static void *connection_thread (void *arg);




int
main (int argc, char **argv)
{
  const char *logfile = NULL;/*"tmp/payprocd.log";*/

  (void)argc;
  (void)argv;
  opt.verbose = 1;
  opt.nodetach = 1;

  /* Set program name etc.  */
  log_set_prefix ("payprocd", JNLIB_LOG_WITH_PREFIX|JNLIB_LOG_WITH_PID);

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

  /* Initialze processing subsystems.  */
  init_tls_subsystem ();

  /* Now start with logging to a file if this is desired. */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, (JNLIB_LOG_WITH_PREFIX
                             |JNLIB_LOG_WITH_TIME
                             |JNLIB_LOG_WITH_PID));
    }

  launch_server ();

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
  /* int rc; */
  /* char *infostr, *p; */
  /* int prot, pid; */

  /* rc = assuan_new (&ctx); */
  /* if (! rc) */
  /*   rc = assuan_socket_connect (ctx, infostr, pid, 0); */
  /* xfree (infostr); */
  /* if (rc) */
  /*   { */
  /*     if (!mode && !silent) */
  /*       log_error ("can't connect to the agent: %s\n", gpg_strerror (rc)); */

  /*     if (ctx) */
  /*       assuan_release (ctx); */
  /*     return -1; */
  /*   } */

  /* if (!opt.quiet && !silent) */
  /*   log_info ("gpg-agent running and available\n"); */

  /* assuan_release (ctx); */
  return 0;
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
          log_set_prefix (NULL, JNLIB_LOG_WITH_PREFIX);
          log_set_file (NULL);
          log_error ("a payprocd process is already running - "
                     "not starting a new one\n");
          *name = 0; /* Inhibit removal of the socket by cleanup(). */
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
launch_server (void)
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
  /* abstime.tv_sec += TIMERTICK_INTERVAL; */

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
          /* handle_tick (); */
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

  cleanup ();
  log_info ("payprocd %s stopped\n", PACKAGE_VERSION);
  npth_attr_destroy (&tattr);
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
          log_info ("payprocd %s stopped\n", PACKAGE_VERSION);
          cleanup ();
          exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
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

  if (opt.verbose)
    log_info ("handler 0x%lx for %p started\n",
              (unsigned long) npth_self (), conn);

  connection_handler (conn);
  if (opt.verbose)
    log_info ("handler 0x%lx for %p terminated\n",
              (unsigned long) npth_self (), conn);

  release_connection_obj (conn);
  return NULL;
}
