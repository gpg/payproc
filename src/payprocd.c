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
#include <pwd.h>
#include <locale.h>  /*(for gpgme)*/
#include <gpgme.h>

#include "util.h"
#include "logging.h"
#include "argparse.h"
#include "commands.h"
#include "tlssupport.h"
#include "cred.h"
#include "journal.h"
#include "session.h"
#include "currency.h"
#include "encrypt.h"
#include "payprocd.h"


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

/* The thread specific data key.  */
static npth_key_t my_tsd_key;

/* The log file.  */
static const char *logfile;



/* Constants to identify the options. */
enum opt_values
  {
    aNull = 0,
    oVerbose	= 'v',
    oAllowUID   = 'U',
    oAllowGID   = 'G',
    oConfig     = 'C',

    oNoConfig   = 500,
    oLogFile,
    oNoLogFile,
    oNoDetach,
    oJournal,
    oStripeKey,
    oPaypalKey,
    oLive,
    oTest,
    oAdminUID,
    oAdminGID,
    oDatabaseKey,
    oBackofficeKey,
    oDebugClient,
    oDebugStripe,

    oLast
  };


/* The list of commands and options. */
static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (301, "@Options:\n "),

  ARGPARSE_s_n (oLive,     "live",      "enable live mode"),
  ARGPARSE_s_n (oTest,     "test",      "enable test mode"),
  ARGPARSE_s_n (oVerbose,  "verbose",   "verbose"),
  ARGPARSE_s_s (oConfig,   "config",    "|FILE|read config from FILE"),
  ARGPARSE_s_n (oNoConfig, "no-config", "ignore default config file"),
  ARGPARSE_s_n (oNoDetach, "no-detach", "run in foreground"),
  ARGPARSE_s_s (oLogFile,  "log-file",  "|FILE|write log output to FILE"),
  ARGPARSE_s_n (oNoLogFile,"no-log-file", "@"),
  ARGPARSE_s_s (oAllowUID, "allow-uid", "|N|allow access from uid N"),
  ARGPARSE_s_s (oAllowGID, "allow-gid", "|N|allow access from gid N"),
  ARGPARSE_s_s (oAdminUID, "admin-uid", "|N|allow admin access from uid N"),
  ARGPARSE_s_s (oAdminGID, "admin-gid", "|N|allow admin access from gid N"),
  ARGPARSE_s_s (oJournal,  "journal",   "|FILE|write the journal to FILE"),
  ARGPARSE_s_s (oStripeKey,
                "stripe-key", "|FILE|read key for Stripe account from FILE"),
  ARGPARSE_s_s (oPaypalKey,
                "paypal-key", "|FILE|read key for PayPal account from FILE"),
  ARGPARSE_s_s (oDatabaseKey,
                "database-key", "|FPR|secret key for the database"),
  ARGPARSE_s_s (oBackofficeKey,
                "backoffice-key", "|FPR|public key for the backoffice"),

  ARGPARSE_s_n (oDebugClient, "debug-client", "debug I/O with the client"),
  ARGPARSE_s_n (oDebugStripe, "debug-stripe", "debug the Stripe REST"),

  ARGPARSE_end ()
};




/* Local prototypes.  */
static void cleanup (void);
static void launch_server (void);
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
set_account_key (const char *fname, int service)
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
      else if (service == 1)
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
      else if (service == 2)
        {
          trim_spaces (buf);
          if (!strchr (buf, ':') && strlen (buf) != 121)
            log_error ("file '%s' seems not to carry a PayPal secret key\n",
                       fname);
          else
            {
              xfree (opt.paypal_secret_key);
              opt.paypal_secret_key = xstrdup (buf);
            }
        }
      fclose (fp);
    }
}


/* Add the UID taken from STRING to the list of allowed clients.  if
   ALSO_ADMIN is set, add that uid also to the list of allowed admin
   users.  */
static void
add_allowed_uid (const char *string, int also_admin)
{
  char *buffer;
  const char *s;
  struct passwd *pw;
  uid_t uid;

  buffer = xstrdup (string);
  trim_spaces (buffer);
  string = buffer;
  if (!*buffer)
    {
      xfree (buffer);
      return;  /* Ignore empty strings.  */
    }
  for (s=string; digitp (s); s++)
    ;
  if (!*s)
    {
      uid = strtoul (string, NULL, 10);
      pw = getpwuid (uid);
      if (pw && pw->pw_uid != uid)
        pw = NULL;
    }
  else
    pw = getpwnam (string);

  if (!pw)
    {
      log_error ("no such user '%s'\n", string);
      xfree (buffer);
      return;
    }
  uid = pw->pw_uid;

  if (opt.n_allowed_uids >= DIM (opt.allowed_uids))
    {
      log_error ("can't add user '%s': Table full\n", string);
      xfree (buffer);
      return;
    }
  if (also_admin && opt.n_allowed_admin_uids >= DIM (opt.allowed_admin_uids))
    {
      log_error ("can't add admin user '%s': Table full\n", string);
      xfree (buffer);
      return;
    }
  opt.allowed_uids[opt.n_allowed_uids++] = uid;
  if (also_admin)
    opt.allowed_admin_uids[opt.n_allowed_admin_uids++] = uid;
}


/* This callback is used by the log functions to return an identifier
   for the current thread.  */
static int
pid_suffix_callback (unsigned long *r_suffix)
{
  unsigned int *idnop;

  idnop = npth_getspecific (my_tsd_key);
  if (!idnop)
    {
      *r_suffix = 0;
      return 0; /* No suffix.  */
    }
  *r_suffix = *idnop;
  return 2; /* Print the suffix in hex format.  */
}


/* The config and command line option parser.  */
static void
parse_options (int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  int default_config = 1;
  const char *configname = NULL;
  unsigned int configlineno;
  FILE *configfp = NULL;
  int live_or_test = 0;

  /* First check whether we have a config file on the commandline.  We
   * also check for the --test and --live flag to decide on the
   * default config name.  */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION;
  while (arg_parse (&pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oConfig:
        case oNoConfig:
          default_config = 0; /* Do not use the default config.  */
          break;
        case oLive: opt.livemode = 1; break;
        case oTest: opt.livemode = 0; break;
        default: break;
        }
    }

  if (default_config)
    configname = (opt.livemode? "/etc/payproc/payprocd.conf"
                  /**/        : "/etc/payproc-test/payprocd.conf");
  opt.livemode = 0;

  /* Parse the option file and the command line. */
  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags = ARGPARSE_FLAG_KEEP;
 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            log_info ("note: default config file '%s': %s\n",
                      configname, strerror (errno));
          else
            {
              log_error ("error opening config file '%s': %s\n",
                         configname, strerror (errno));
              exit (2);
            }
          configname = NULL;
          default_config = 0;
        }
    }
  while (optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oVerbose:  opt.verbose++; break;
        case oDebugClient: opt.debug_client++; break;
        case oDebugStripe: opt.debug_stripe++; break;
        case oNoDetach: opt.nodetach = 1; break;
        case oLogFile:  logfile = pargs.r.ret_str; break;
        case oNoLogFile: logfile = NULL; break;
        case oJournal:  jrnl_set_file (pargs.r.ret_str); break;
        case oAllowUID: add_allowed_uid (pargs.r.ret_str, 0); break;
        case oAllowGID: /*FIXME*/ break;
        case oAdminUID: add_allowed_uid (pargs.r.ret_str, 1); break;
        case oAdminGID: /*FIXME*/ break;
        case oStripeKey: set_account_key (pargs.r.ret_str, 1); break;
        case oPaypalKey: set_account_key (pargs.r.ret_str, 2); break;
        case oLive: opt.livemode = 1; live_or_test = 1; break;
        case oTest: opt.livemode = 0; live_or_test = 1; break;

        case oDatabaseKey:
          xfree (opt.database_key_fpr);
          opt.database_key_fpr = xstrdup (pargs.r.ret_str);
          break;
        case oBackofficeKey:
          xfree (opt.backoffice_key_fpr);
          opt.backoffice_key_fpr = xstrdup (pargs.r.ret_str);
          break;

        case oConfig:
          if (!configfp)
            {
              configname = pargs.r.ret_str;
              goto next_pass;
            }
          /* Ignore this option in config files (no nesting).  */
          break;
        case oNoConfig: break; /* Already handled.  */

        default:
          pargs.err = configfp? ARGPARSE_PRINT_WARNING : ARGPARSE_PRINT_ERROR;
          break;
	}
    }
  if (configfp)
    {
      fclose (configfp);
      configfp = NULL;
      configname = NULL;
      goto next_pass;
    }

  if (argc)
    usage (1);

  if (!live_or_test)
    log_info ("implicitly using --test\n");
}


int
main (int argc, char **argv)
{
  /* Set program name etc.  */
  set_strusage (my_strusage);
  log_set_prefix ("payprocd", JNLIB_LOG_WITH_PREFIX);

  /* Make sure that our subsystems are ready.  */
  gpgrt_init ();
  gpgrt_set_syscall_clamp (npth_unprotect, npth_protect);
  /* Access the standard estreams as early as possible.  If we don't
     do this the original stdio streams may have been closed when
     _es_get_std_stream is first use and in turn it would connect to
     the bit bucket.  */
  {
    int i;
    for (i=0; i < 3; i++)
      (void)_gpgrt_get_std_stream (i);
  }

  npth_init ();

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  if (!npth_key_create (&my_tsd_key, NULL))
    if (!npth_setspecific (my_tsd_key, NULL))
      log_set_pid_suffix_cb (pid_suffix_callback);


  /* Check that Libgcrypt is suitable.  */
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal ("%s is too old (need %s, have %s)\n", "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  /* Initialze processing subsystems.  */
  init_tls_subsystem ();

  /* Init GPGME.  */
  setlocale (LC_ALL, "");
  if (!gpgme_check_version (NEED_GPGME_VERSION))
    log_fatal ("%s is too old (need %s, have %s)\n", "gpgme",
               NEED_GPGME_VERSION, gpgme_check_version (NULL));
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  parse_options (argc, argv);

  if (opt.livemode && (!opt.stripe_secret_key
                       || strncmp (opt.stripe_secret_key, "sk_live_", 8)))
    log_error ("live mode requested but no live key given\n");
  else if (!opt.livemode
           && opt.stripe_secret_key
           && !strncmp (opt.stripe_secret_key, "sk_live_", 8))
    log_error ("test mode requested but live key given\n");

  encrypt_setup_keys ();

  if (log_get_errorcount (0))
    exit (2);

  if (opt.verbose)
    {
      int i, j, star;

      log_info ("Mode .........: %s\n", opt.livemode? "live" : "test");
      log_info ("Stripe key ...: %s\n", opt.stripe_secret_key? "yes":"no");
      log_info ("Paypal key ...: %s\n", opt.paypal_secret_key? "yes":"no");
      encrypt_show_keys ();
      log_info ("Allowed users :");
      for (i=0; i < opt.n_allowed_uids; i++)
        {
          for (j=star=0; j < opt.n_allowed_admin_uids && !star; j++)
            if (opt.allowed_admin_uids[j] == opt.allowed_uids[i])
              star = 1;
          log_printf (" %lu%s", (unsigned long)opt.allowed_uids[i],
                      star? "*":"");
        }
      log_printf ("\n");
    }

  /* Start the server.  */
  launch_server ();

  return 0;
}


/* Cleanup handler - usually called via atexit.  */
static void
cleanup (void)
{
  static int done;
  char *p;

  if (done)
    return;
  done = 1;

  if (remove_socket_flag)
    remove (server_socket_name ());

  p = opt.database_key_fpr;
  opt.database_key_fpr = NULL;
  xfree (p);
  p = opt.backoffice_key_fpr;
  opt.backoffice_key_fpr = NULL;
  xfree (p);
  encrypt_release_keys ();
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
create_socket (const char *name)
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
launch_server (void)
{
  int fd;

  fd = create_socket (server_socket_name ());
  fflush (NULL);
  if (!opt.nodetach)
    {
      pid_t pid;

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
    }

  /*
   * This is the child (or the main process in case of --no-detach)
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
  read_exchange_rates ();
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
  static int count;

  (void)arg;

  count++;

  if (sentinel)
    {
      log_info ("only one cleaning person at a time please\n");
      return NULL;
    }
  sentinel++;
  if (opt.verbose > 1)
    log_info ("starting housekeeping\n");

  session_housekeeping ();

  /* Stuff we do only every hour:  */
  if (count >= 3600 / HOUSEKEEPING_INTERVAL)
    {
      count = 0;
      read_exchange_rates ();
    }

  if (opt.verbose > 1)
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


/* Return the name of the socket.  */
const char *
server_socket_name (void)
{
  return opt.livemode? PAYPROCD_SOCKET_NAME : PAYPROCD_TEST_SOCKET_NAME;
}


void
shutdown_server (void)
{
  kill (getpid(), SIGTERM);
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
  unsigned int idno;
  pid_t pid;
  uid_t uid;
  gid_t gid;

  idno = id_from_connection_obj (conn);
  npth_setspecific (my_tsd_key, &idno);

  if (credentials_from_socket (fd_from_connection_obj (conn), &pid, &uid, &gid))
    {
      log_error ("credentials missing - closing\n");
      goto leave;
    }

  active_connections++;
  if (opt.verbose)
    log_info ("new connection - pid=%u uid=%u gid=%u\n",
              (unsigned int)pid, (unsigned int)uid, (unsigned int)gid);

  connection_handler (conn, uid);

  if (opt.verbose)
    log_info ("connection terminated\n");
  active_connections--;

 leave:
  release_connection_obj (conn);
  npth_setspecific (my_tsd_key, NULL);  /* To be safe.  */
  return NULL;
}
