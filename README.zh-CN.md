# JailMCP

**JailMCP — 把越狱 iPhone 变成 MCP 服务器。**

JailMCP 是面向越狱 iOS 的**客户端中立 MCP 服务器**。它把手机本地能力通过认证过的回环接口暴露出来：

- 文件与项目根
- 无沙箱的 mobile Shell
- 进程与设备状态
- Frida：进程列表、spawn/attach、ObjC hook、长期 session 和日志
- 审计与结构化错误

Minis 只是受支持的 MCP 客户端之一，不是项目归属。任何能访问 `127.0.0.1` 的 MCP 客户端都可以使用。

## 当前状态

项目正在从 **OpenMinis-Jailbreak** 分阶段改名为 **JailMCP**。

| 层级 | 0.4.0 状态 |
|---|---|
| 品牌 / 仓库 | JailMCP / `jailmcp` |
| 当前运行包 | `0.3.13-2+experimental` |
| bridge | `0.3.11` |
| 包名 | 仍是 `app.openminis.jailbreak` |
| MCP 工具 | 37 个，包含原生 `jb_frida_*` |
| MCP 地址 | `http://127.0.0.1:18765/mcp` |

0.4.0 只改品牌，包名、launchd、状态目录和工具名都不动，保证现有安装继续升级、token 不丢。新的 `dev.jailmcp.bridge` 包在 0.5.0 落地。

## 命名

```text
品牌          JailMCP
中文          越狱 MCP
仓库          jailmcp
守护进程      jailmcpd
CLI           jailmcp
MCP server    jailmcp
工具前缀      jb_*        （jb = jailbreak，永久保留）
主包          dev.jailmcp.bridge       （0.5.0）
Frida 包      dev.jailmcp.frida-cli   （0.5.0）
状态目录      .jailmcp                （0.5.0）
```

完整迁移表见 [NAMING.md](NAMING.md)。

## 原生 Frida 工具

```text
jb_frida_ps
jb_frida_run
jb_frida_start
jb_frida_logs
jb_frida_stop
jb_frida_sessions
```

`jb_frida_start` 返回 session id 和日志路径；`jb_frida_logs` 按 offset 读取新输出；`jb_frida_stop` 结束 session。

spawn 需要设备解锁。Frida server 是 root 服务，只监听 `127.0.0.1:27042`；客户端以 `mobile` 运行。

## 安全边界

- 只监听 `127.0.0.1`
- Bearer token，0600
- `allow_mobile_shell` 是 shell/Frida 的总开关
- bridge 内没有 root helper
- Frida server 是唯一的 root 组件
- 不要把 Frida 或 MCP 绑到 `0.0.0.0`

## 路线

```text
0.4.0  品牌：JailMCP、仓库、文档、MCP server name
       包名 / 路径 / 工具名不变

0.5.0  dev.jailmcp.bridge + dev.jailmcp.frida-cli
       .jailmcp 状态目录
       从旧包和旧路径迁移

1.0.0  移除旧包名
       jb_* 工具名永久保留
```

## 旧文档

旧版说明保留在 [docs/legacy-0.3.12.md](docs/legacy-0.3.12.md)。
