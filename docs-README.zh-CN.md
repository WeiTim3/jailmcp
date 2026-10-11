# OpenMinis-Jailbreak 0.3.3-1+experimental

以 launchd 服务形式运行、并通过本机 MCP 向 OpenMinis 提供越狱侧能力的服务包。
OpenMinis 本体不需要越狱权限、不需要注入。

## 本版改动

1. **修复 `jb_process_list`**：原先执行相对命令 `ps`，而守护进程 PATH 为
   `/usr/bin:/bin:/usr/sbin:/sbin`，不含越狱工具目录，目标设备上 `ps` 仅存在于
   `/rootfs/bin/ps`。现按固定候选顺序（`/rootfs/bin/ps` → `/bin/ps` → `/usr/bin/ps`
   → `/usr/local/bin/ps`）探测可执行文件，再用绝对路径执行；候选为常量，不接受调用者输入。
2. **修复 `jb_device_info` 缺少真实系统版本**：原先只返回 `uname` 的内核版本，
   不能用来推断 iOS 版本。现读取 `/System/Library/CoreServices/SystemVersion.plist`，
   返回 `{"version": "16.4.1", "build": "20E252"}`；读取失败时为 `null`，不影响其余字段。
3. **放宽重装限制**：`preinst` 不再因存在旧版本号参数就拒绝，而是只读查询 dpkg 状态——
   仅当记录为“已安装”时拒绝覆盖；卸载后残留的 `config-files` 记录允许直接重新安装，
   **不再要求手动 `dpkg --purge`**。拒绝前唯一的动作是一次只读状态查询。

两项修复均为只读逻辑，未改变权限模型，未新增 root 能力。

## 生命周期

- `preinst install`：root 与 UID501 预检；判断是否会覆盖已安装载荷；失败不修改任何文件。
- `postinst configure`：UID501 创建 canonical 目录、私有 token/state 与固定 launchd 服务，并做健康检查。
- `prerm remove`：只停止并验证本包同标签服务及其自有子进程；不删 token/state。
- `postrm remove/purge`：依据 root 所有的凭据，只清理本包的 `.bridge-state`
  （token、配置、版本、审计、锁、临时文件）；保留 canonical 目录内的普通项目文件。
  缺失文件、重复执行与可选清理失败仅警告，不让脚本失效。

监督器信号处理只设置 STOP 标志；退出时对自有子进程组做有界 TERM/KILL；
子进程另带父进程消失看门狗，即使监督器被强制结束也会立即退出并释放端口。

## 安装

唯一项目目录为 `/var/mobile/Documents/OpenMinis-Jailbreak`，**不创建也不接受小写 alias**。
若发现大写目录、小写 alias、同标签服务或其它运行时残留，将拒绝并保留现场。

安装后 Token 位于 `/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state/token`（私密，勿分享）；
OpenMinis 侧 MCP 服务器填 `http://127.0.0.1:18765/mcp`，请求头 `Authorization: Bearer <token>`。

## 版本兼容

本包为 **干净安装** 语义：拒绝覆盖 dpkg 记录为“已安装”的版本。
从旧版本迁移前请先卸载并私下备份数据。安装包版本 `0.3.3-1+experimental`，
移动端 bridge `0.3.3`，MCP API 版本仍为 `3`。

## 未验证项

安装、卸载、重启恢复与自身更新链路的真机验收尚未覆盖本版本；
本机测试运行于 Python 3.12，Python 3.9 仅做语法解析。详见 `TEST_REPORT_0331.txt`。
