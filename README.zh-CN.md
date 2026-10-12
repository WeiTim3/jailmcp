# OpenMinis-Jailbreak 0.3.6-1+experimental

以 launchd 服务形式运行、并通过本机 MCP 向 OpenMinis 提供越狱侧能力的服务包。
OpenMinis 本体不需要越狱权限、不需要注入。

## 本版改动（0.3.6）

**支持原地升级，不再需要先卸载。** 在 Sileo 里直接更新即可：

- `preinst upgrade`：完整预检（root、dpkg 架构 `iphoneos-arm64e`、Roothide 根映射、mobile 身份与组）；
  校验已安装运行时是否命中已知良好白名单（0.3.3-1、0.3.5-1 与本版）、plist 形状是否正确；
  把旧运行时、plist 与移动端 active 指针快照到 `/usr/local/lib/openminis-jb-transaction`
  （root 所有、0700，含 boot id）；随后有界停止服务并确认监听端口已释放。
  **任何一步失败都在任何改动之前中止**，并保证服务重新运行。
- `postinst configure`：确保 plist 与 root 运行时为本包版本；以 UID501 只读核对 token/config/audit
  指纹未变；若打包 `bridge.py` 与当前 active 版本不同，则入 `versions-v030/` 并**原子**切换
  active 指针（`previous` = 旧 active，`jb_rollback` 依旧可用）；启动服务并做认证健康检查；
  成功即标记提交并丢弃快照。
- 失败时：按快照回滚 root 运行时、plist 与移动端 active 指针，重启旧版本，并以非零状态退出
  （dpkg 可正常收尾）。全程不清理、不重置 token／配置／审计／版本目录。
- 移动端 `bridge.py` 版本号升到 `0.3.6`（功能与 0.3.5 相同，用于演练版本切换）；
  `launcher.py`、`maintenance_runtime.py`、`mobile_setup.py` 逐字节未变。

快照只有在“同一 boot、且记录的内容与磁盘现状一致”时才可能被替换/复用，否则拒绝并保留现场；
这覆盖上一次失败留下的快照、跨 boot 快照、未知/混合运行时、plist 不符、active 版本目录缺失等情况。

## 历史改动（0.3.5）

1. **新增 `jb_mkdir`**：只建一级目录（`parents=true` 才逐段创建），路径规则与其它文件工具一致
   （项目根内相对路径、逐段 `O_NOFOLLOW`、`.bridge-state` 拒绝）；叶子已存在时拒绝并说明是目录／文件／符号链接；
   `mode` 只接受 0700..0777，在收紧 umask 下创建再精确设权，结果不会超出请求的 mode。
2. **新增暂存式原子分块上传**：`jb_upload_begin` / `jb_upload_chunk` / `jb_upload_commit` / `jb_upload_abort`。
   暂存数据放在私有状态目录的 `uploads-v030/`，文件工具无法到达，提交前项目里不可见；
   并发上传上限 4、暂存总量上限 256 MiB，过期暂存仅由有界清扫或显式 abort 处理。
   `jb_upload_commit` 校验装配哈希后用**一次 `os.replace`** 就位，目标要么是旧文件要么是完整新文件，
   绝无半成品；`jb_write_chunk` 的多分片写入**不是**原子操作，这里是其原子替代。
   目标已存在且未 `overwrite=true`、目标是目录／符号链接／硬链接、目标是 `.bridge-state` 时一律拒绝。
3. 本版共 25 个工具（原有 20 个的行为与 schema 完全不变），MCP API 仍为 `3`；
   仍只修改移动端 `bridge.py`＋测试与文档，`maintenance_runtime.py` 与 `launcher.py` 未变，可经自身更新链路下发。

## 历史改动（0.3.4）

1. **新增 8 个文件接口工具**：`jb_list_dir`、`jb_stat`、`jb_delete`、`jb_rename`、
   `jb_search`、`jb_read_chunk`、`jb_write_chunk`、`jb_projects`。全部只接受已配置项目根
   内的相对路径，复用既有 dirfd + `O_NOFOLLOW` 逐段遍历；`.bridge-state` 与项目根本身
   对所有新工具不可达；列举／递归删除／搜索均有硬上限并明确报错，不静默截断；
   符号链接一律不跟随。`jb_write_chunk` 的分片写入不是原子操作，仅当显式提供
   `expected_sha256` 时具备并发修改保护。本版只改移动端 `bridge.py`＋测试，
   可经自身更新链路下发，无需重装。
2. **修复 `jb_process_list`**：原先执行相对命令 `ps`，而守护进程 PATH 为
   `/usr/bin:/bin:/usr/sbin:/sbin`，不含越狱工具目录，目标设备上 `ps` 仅存在于
   `/rootfs/bin/ps`。现按固定候选顺序（`/rootfs/bin/ps` → `/bin/ps` → `/usr/bin/ps`
   → `/usr/local/bin/ps`）探测可执行文件，再用绝对路径执行；候选为常量，不接受调用者输入。
2. **修复 `jb_device_info` 缺少真实系统版本**：原先只返回 `uname` 的内核版本，
   不能用来推断 iOS 版本。现读取 `/System/Library/CoreServices/SystemVersion.plist`，
   返回 `{"version": "16.4.1", "build": "20E252"}`；读取失败时为 `null`，不影响其余字段。
3. **放宽重装限制**：`preinst` 不再因存在旧版本号参数就拒绝，而是只读查询 dpkg 状态——
   仅当记录为“已安装”时拒绝覆盖；卸载后残留的 `config-files` 记录允许直接重新安装，
   **不再要求手动 `dpkg --purge`**。拒绝前唯一的动作是一次只读状态查询。

以上变更均未改变权限模型，未新增 root 能力，也未提供任何可扩大授权根的工具。

## 生命周期

- `preinst install`：root 与 UID501 预检；判断是否会覆盖已安装载荷；失败不修改任何文件。
- `preinst upgrade`：白名单校验已安装运行时与 plist；快照旧运行时／plist／active 指针；有界停止服务。
- `postinst configure`：UID501 创建 canonical 目录、私有 token/state 与固定 launchd 服务，并做健康检查；
  若是一次升级，则对账移动端版本（必要时原子切换 active 指针）后启动服务并验证，
  成功提交、失败按快照回滚并重启旧版本。
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

0.3.6 起支持 **原地升级**：在 Sileo 中直接更新即可，token、配置、审计与已下发的版本目录都保持不变，
OpenMinis 侧无需重填 token。可原地升级的旧版本为白名单内的 0.3.3-1 与 0.3.5-1；
更早的版本（例如 0.3.2 系列）仍请先卸载再安装（卸载后可直接重装，不必 purge）。
安装包版本 `0.3.6-1+experimental`，移动端 bridge `0.3.6`，MCP API 版本仍为 `3`。

## 工具

本版共 25 个工具：原有 12 个（设备信息、进程、维护状态、读写/编辑文件、执行命令、更新与回退）
+ 0.3.4 的 8 个文件接口（列目录、元信息、删除、重命名、搜索、分块读、分块写、项目列表）
+ 0.3.5 的 5 个（建目录、暂存上传 begin/chunk/commit/abort）。详见 README.md 的工具表。

## 关键修复

`os.listdir(fd)` 在 Python 3.9（设备运行时）会关闭该描述符，而 3.12 不会；原先列举后复用
同一 dirfd 的代码在真机上必然失败，且启动健康检查无法发现。现通过 `dup` 后的副本列举。

## 未验证项

本版本的真机**原地升级**验收尚未完成（升级路径已由离线模拟的完整 dpkg 序列覆盖，
见 `test_upgrade.py`：26 项）；安装、卸载、重启恢复与自身更新链路的真机验收沿用上一版结论。
本机测试运行于 Python 3.12，Python 3.9 仅做语法解析。详见 `TEST_REPORT_0361.txt`。
