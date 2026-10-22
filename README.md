# JailMCP

**JailMCP — Jailbroken iOS as an MCP endpoint.**

[中文说明](README.zh-CN.md)

JailMCP is a client-neutral **MCP server for jailbroken iOS**. It exposes the
phone's local capabilities over an authenticated loopback endpoint:

- files and project roots
- sandbox-free mobile shell
- process and device status
- Frida: process list, spawn/attach, ObjC hooks, long-lived sessions and logs
- audit and structured errors

Minis is one supported MCP client, not the owner of the project. Any MCP client
that can reach `127.0.0.1` can use it.

## Status

The project is in a staged rename from **OpenMinis-Jailbreak** to **JailMCP**.

| Layer | 0.4.0 state |
|---|---|
| Brand / repository | JailMCP / `jailmcp` |
| Current runtime package | `0.3.13-2+experimental` |
| Bridge version | `0.3.11` |
| Package ID | `app.openminis.jailbreak` (0.5.0 moves to `dev.jailmcp.bridge`) |
| MCP tools | 37, including native `jb_frida_*` |
| MCP endpoint | `http://127.0.0.1:18765/mcp` |

The package ID, launchd label, state directory and tool names are intentionally
unchanged in 0.4.0 so existing installs keep upgrading and keep their token.
0.5.0 introduces `dev.jailmcp.bridge`; runtime paths and `.bridge-state` stay for one more release.

## Naming

```text
Brand          JailMCP
Chinese        越狱 MCP
Repository     jailmcp
Daemon         jailmcpd
CLI            jailmcp
MCP server     jailmcp
Tools          jb_*        (jb = jailbreak, kept permanently)
Package        dev.jailmcp.bridge       (0.5.0)
Frida package  dev.jailmcp.frida-cli   (0.5.0)
State          .jailmcp                (0.5.0)
```

See [NAMING.md](NAMING.md) for the full naming and migration table.

## Native Frida tools

JailMCP currently exposes:

```text
jb_frida_ps
jb_frida_run
jb_frida_start
jb_frida_logs
jb_frida_stop
jb_frida_sessions
```

`jb_frida_start` returns a session id and a log path. `jb_frida_logs` reads new
output by offset; `jb_frida_stop` terminates the client session.

Spawn requires an unlocked device. The Frida server itself is a root service
bound to `127.0.0.1:27042`; the client runs as `mobile`.

## Security model

- only loopback (`127.0.0.1`)
- bearer token, mode 0600
- `allow_mobile_shell` is the master switch for shell/Frida execution
- no root helper inside the bridge
- Frida server is the only root component
- do not bind Frida or MCP to `0.0.0.0`

## Roadmap

```text
0.4.0  brand: JailMCP, repository, docs, MCP server name
       package IDs / paths / tools unchanged

0.5.0  dev.jailmcp.bridge + dev.jailmcp.frida-cli
       package IDs move; runtime paths/state stay for compatibility

0.6.0  .jailmcp state directory and /usr/local/lib/jailmcp
       token/config migration

1.0.0  remove legacy package and paths
       jb_* tool names remain permanent
```

## Legacy documentation

The previous README is preserved at [docs/legacy-0.3.12.md](docs/legacy-0.3.12.md).

