# JailMCP naming

## Final identity

```text
Brand          JailMCP
Chinese        越狱 MCP
Tagline        Jailbroken iOS as an MCP endpoint.
Repository     jailmcp
Python package jailmcp
Daemon         jailmcpd
CLI            jailmcp
MCP server     jailmcp
Config         jailmcp.json
State          .jailmcp
Env prefix     JAILMCP_*
```

## Packages and paths

```text
Main package       dev.jailmcp.bridge
Frida package      dev.jailmcp.frida-cli
LaunchDaemon       dev.jailmcp.bridge
Program directory  /usr/local/lib/jailmcp
Binaries           /usr/local/bin/jailmcp
                   /usr/local/bin/jailmcpd
MCP endpoint       http://127.0.0.1:18765/mcp
```

## Tools

`jb_` means **jailbreak**. It is kept permanently; there is no `phone_*`
migration.

```text
jb_device_info
jb_projects
jb_exec
jb_process_list

jb_read_file
jb_write_file
jb_edit_file
jb_read_chunk
jb_write_chunk
jb_upload_begin
jb_upload_chunk
jb_upload_commit
jb_upload_abort

jb_list_dir
jb_stat
jb_delete
jb_rename
jb_chmod
jb_copy
jb_symlink
jb_readlink
jb_search
jb_find
jb_log_tail

jb_frida_ps
jb_frida_run
jb_frida_start
jb_frida_logs
jb_frida_stop
jb_frida_sessions
```

## Migration

| Old | New | Release |
|---|---|---|
| OpenMinis-Jailbreak | JailMCP | 0.4.0 |
| `openminis-jb` server name | `jailmcp` | 0.4.0 |
| `app.openminis.jailbreak` | `dev.jailmcp.bridge` | 0.5.0 |
| `app.openminis.jbbridge` | `dev.jailmcp.bridge` | 0.5.0 |
| `/usr/local/lib/openminis-jb` | `/usr/local/lib/jailmcp` | 0.5.0 |
| `.bridge-state` | `.jailmcp` | 0.5.0 |
| `jb_*` tools | unchanged | permanent |

The old package/path/state names remain valid through the migration release.
Do not rename package IDs and paths in the same release as the brand.
