/*
 * frida-ondevice: a small Frida client that runs on the iPhone itself.
 *
 * It talks to a frida-server listening on 127.0.0.1:27042 (installed by the
 * re.frida.server package) and does not need a computer.
 *
 * Usage:
 *   frida ps
 *   frida run -p PID -l script.js
 *   frida run -n ProcessName -l script.js
 *   frida run -n ProcessName -e 'console.log("hi")'
 *   frida run -f com.apple.Preferences -e 'console.log("hi")'
 */
#include "frida-core.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GMainLoop *loop = NULL;
static FridaScript *active_script = NULL;
static FridaSession *active_session = NULL;

static void
on_message (FridaScript *script, const gchar *message, GBytes *data,
            gpointer user_data)
{
  (void) script;
  (void) data;
  (void) user_data;
  g_print ("%s\n", message);
  fflush (stdout);
}

static void
on_detached (FridaSession *session, FridaSessionDetachReason reason,
             FridaCrash *crash, gpointer user_data)
{
  (void) session;
  (void) crash;
  (void) user_data;
  g_printerr ("[*] detached: %d\n", reason);
  if (loop != NULL)
    g_main_loop_quit (loop);
}

static void
on_signal (int signo)
{
  (void) signo;
  if (loop != NULL)
    g_main_loop_quit (loop);
}

static FridaDevice *
open_device (FridaDeviceManager *manager, const gchar *address)
{
  GError *error = NULL;
  FridaDevice *device =
      frida_device_manager_add_remote_device_sync (manager, address, NULL, NULL, &error);
  if (device == NULL)
    {
      g_printerr ("cannot connect to frida-server at %s: %s\n",
                  address, error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
    }
  return device;
}

static int
cmd_ps (FridaDeviceManager *manager, const gchar *address)
{
  GError *error = NULL;
  FridaDevice *device = open_device (manager, address);
  if (device == NULL)
    return 1;

  FridaProcessList *processes =
      frida_device_enumerate_processes_sync (device, NULL, NULL, &error);
  if (processes == NULL)
    {
      g_printerr ("cannot enumerate processes: %s\n",
                  error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
      g_object_unref (device);
      return 1;
    }

  gint count = frida_process_list_size (processes);
  for (gint i = 0; i != count; i++)
    {
      FridaProcess *process = frida_process_list_get (processes, i);
      g_print ("%u\t%s\n", frida_process_get_pid (process),
               frida_process_get_name (process));
      g_object_unref (process);
    }

  g_object_unref (processes);
  g_object_unref (device);
  return 0;
}

static guint
find_pid (FridaDevice *device, const gchar *name)
{
  GError *error = NULL;
  FridaProcessList *processes =
      frida_device_enumerate_processes_sync (device, NULL, NULL, &error);
  if (processes == NULL)
    {
      g_printerr ("cannot enumerate processes: %s\n",
                  error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
      return 0;
    }

  guint pid = 0;
  gint count = frida_process_list_size (processes);
  for (gint i = 0; i != count; i++)
    {
      FridaProcess *process = frida_process_list_get (processes, i);
      if (g_strcmp0 (frida_process_get_name (process), name) == 0)
        {
          pid = frida_process_get_pid (process);
          g_object_unref (process);
          break;
        }
      g_object_unref (process);
    }
  g_object_unref (processes);
  return pid;
}

static int
cmd_run (FridaDeviceManager *manager, const gchar *address,
         guint pid, const gchar *process_name, const gchar *spawn_id,
         const gchar *script_path, const gchar *inline_script)
{
  GError *error = NULL;
  FridaDevice *device = open_device (manager, address);
  if (device == NULL)
    return 1;

  gboolean spawned = FALSE;
  if (spawn_id != NULL)
    {
      pid = frida_device_spawn_sync (device, spawn_id, NULL, NULL, &error);
      if (pid == 0)
        {
          g_printerr ("cannot spawn %s: %s\n", spawn_id,
                      error != NULL ? error->message : "unknown error");
          if (error != NULL) g_error_free (error);
          g_object_unref (device);
          return 1;
        }
      spawned = TRUE;
    }
  else
    {
      if (pid == 0 && process_name != NULL)
        pid = find_pid (device, process_name);
      if (pid == 0)
        {
          g_printerr ("process not found\n");
          g_object_unref (device);
          return 1;
        }
    }

  gchar *source = NULL;
  gsize source_len = 0;
  if (inline_script != NULL)
    {
      source = g_strdup (inline_script);
    }
  else if (!g_file_get_contents (script_path, &source, &source_len, &error))
    {
      g_printerr ("cannot read %s: %s\n", script_path,
                  error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
      g_object_unref (device);
      return 1;
    }

  active_session = frida_device_attach_sync (device, pid, NULL, NULL, &error);
  if (active_session == NULL)
    {
      g_printerr ("cannot attach to %u: %s\n", pid,
                  error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
      g_free (source);
      g_object_unref (device);
      return 1;
    }

  g_signal_connect (active_session, "detached", G_CALLBACK (on_detached), NULL);

  FridaScriptOptions *options = frida_script_options_new ();
  frida_script_options_set_name (options, "frida-ondevice");
  frida_script_options_set_runtime (options, FRIDA_SCRIPT_RUNTIME_QJS);
  active_script = frida_session_create_script_sync (
      active_session, source, options, NULL, &error);
  g_object_unref (options);
  g_free (source);

  if (active_script == NULL)
    {
      g_printerr ("cannot create script: %s\n",
                  error != NULL ? error->message : "unknown error");
      if (error != NULL)
        g_error_free (error);
      frida_session_detach_sync (active_session, NULL, NULL);
      g_object_unref (active_session);
      g_object_unref (device);
      return 1;
    }

  g_signal_connect (active_script, "message", G_CALLBACK (on_message), NULL);
  frida_script_load_sync (active_script, NULL, &error);
  if (error != NULL)
    {
      g_printerr ("cannot load script: %s\n", error->message);
      g_error_free (error);
      frida_script_unload_sync (active_script, NULL, NULL);
      frida_session_detach_sync (active_session, NULL, NULL);
      g_object_unref (active_script);
      g_object_unref (active_session);
      g_object_unref (device);
      return 1;
    }

  if (spawned)
    {
      frida_device_resume_sync (device, pid, NULL, &error);
      if (error != NULL)
        {
          g_printerr ("cannot resume %u: %s\n", pid, error->message);
          g_error_free (error);
        }
    }

  g_print ("[*] attached %u, script loaded; Ctrl-C to stop\n", pid);
  fflush (stdout);

  loop = g_main_loop_new (NULL, TRUE);
  signal (SIGINT, on_signal);
  signal (SIGTERM, on_signal);
  g_main_loop_run (loop);
  g_main_loop_unref (loop);
  loop = NULL;

  frida_script_unload_sync (active_script, NULL, NULL);
  g_object_unref (active_script);
  active_script = NULL;
  frida_session_detach_sync (active_session, NULL, NULL);
  g_object_unref (active_session);
  active_session = NULL;
  g_object_unref (device);
  return 0;
}

static void
usage (const char *argv0)
{
  g_printerr ("usage:\n  %s ps\n  %s run -p PID -l script.js\n  %s run -n NAME -l script.js\n  %s run -f BUNDLE_ID -e 'code'\n",
              argv0, argv0, argv0, argv0);
}

int
main (int argc, char *argv[])
{
  if (argc < 2)
    {
      usage (argv[0]);
      return 1;
    }

  gchar *address = g_strdup ("127.0.0.1:27042");
  guint pid = 0;
  gchar *name = NULL;
  gchar *spawn_id = NULL;
  gchar *script = NULL;
  gchar *inline_script = NULL;
  gchar *command = g_strdup (argv[1]);

  for (int i = 2; i < argc; i++)
    {
      if (g_strcmp0 (argv[i], "-H") == 0 && i + 1 < argc)
        {
          g_free (address);
          address = g_strdup (argv[++i]);
        }
      else if (g_strcmp0 (argv[i], "-p") == 0 && i + 1 < argc)
        pid = (guint) g_ascii_strtoull (argv[++i], NULL, 10);
      else if (g_strcmp0 (argv[i], "-n") == 0 && i + 1 < argc)
        name = g_strdup (argv[++i]);
      else if (g_strcmp0 (argv[i], "-f") == 0 && i + 1 < argc)
        spawn_id = g_strdup (argv[++i]);
      else if (g_strcmp0 (argv[i], "-l") == 0 && i + 1 < argc)
        script = g_strdup (argv[++i]);
      else if (g_strcmp0 (argv[i], "-e") == 0 && i + 1 < argc)
        inline_script = g_strdup (argv[++i]);
      else
        {
          usage (argv[0]);
          g_free (command); g_free (address); g_free (name); g_free (script);
          return 1;
        }
    }

  frida_init ();
  FridaDeviceManager *manager = frida_device_manager_new ();
  int rc = 1;

  if (g_strcmp0 (command, "ps") == 0)
    rc = cmd_ps (manager, address);
  else if (g_strcmp0 (command, "run") == 0 && (script != NULL || inline_script != NULL))
    rc = cmd_run (manager, address, pid, name, spawn_id, script, inline_script);
  else
    usage (argv[0]);

  frida_device_manager_close_sync (manager, NULL, NULL);
  g_object_unref (manager);

  g_free (command);
  g_free (address);
  g_free (name);
  g_free (spawn_id);
  g_free (script);
  g_free (inline_script);
  return rc;
}
