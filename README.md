# OpenMinis-Jailbreak

给 [OpenMinis](https://openminis.app) 增加越狱侧能力的本地服务包。它以 iOS 越狱环境中的
launchd 服务形式运行，并作为 MCP（Model Context Protocol）服务器暴露一组工具，供 OpenMinis
通过 `127.0.0.1` 调用。

**OpenMinis 本体不需要越狱权限、不需要注入、不需要改签名。** App 只做一件普通事：连本机回环端口。

```
OpenMinis（普通沙盒 App）
    │  http://127.0.0.1:18765/mcp  + Bearer 认证
    ▼
launchd → 监督器（root 所有，以 mobile 运行）
    ▼
bridge.py（mobile，UID 501）
    ├── 文件读写 / 精确编辑
    ├── 执行 mobile 命令
    ├── 设备与系统信息
    └── 自身更新与回退
```

## 环境要求

- Dopamine Roothide（rootless）越狱，iOS 16.x
- 越狱侧 Python 3.9（`python3` / `python3.9` / `libpython3.9`）
- `roothide`、`launchctl`

## 安装

下载 `dist/` 下的 `.deb`，用 Filza 打开安装，或在支持本地 DEB 的 Sileo 中安装。
安装后 OpenMinis 侧添加 MCP 服务器：

| 字段 | 值 |
|---|---|
| 名称 | `openminis-jb`（任意） |
| 传输 | HTTP |
| URL | `http://127.0.0.1:18765/mcp` |
| 请求头 | `Authorization` = `Bearer <本机 token>` |
| 授权 | None |

本机 token 位于（属于私密数据，不要提交或分享）：

```
/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state/token
```

## 工具一览

| 工具 | 作用 | 验证状态 |
|---|---|---|
| `jb_device_info` | 内核、机型、真实系统版本、UID、PID、版本与源码哈希 | ✅ |
| `jb_maintenance_info` | 权限边界、项目目录、版本、监督器状态 | ✅ |
| `jb_exec` | 以 mobile 身份执行命令 | ✅ |
| `jb_read_file` | 读取项目文件（Base64 + SHA256） | ✅ |
| `jb_write_file` | 原子创建／覆盖，支持 SHA256 比对 | ✅ |
| `jb_edit_file` | 精确替换唯一匹配 | ✅ |
| `jb_restart` | 远程重启服务 | ✅ |
| `jb_process_list` | 进程列表（解析 `ps` 绝对路径后执行） | ⚠️ 修复待真机确认 |
| `jb_stage_update` | 暂存新版 bridge 并校验哈希／语法 | ⚠️ 未真机验证 |
| `jb_validate_update` | 复核暂存版本 | ⚠️ 未真机验证 |
| `jb_apply_update` | 应用更新，健康检查失败自动回退 | ⚠️ 未真机验证 |
| `jb_rollback` | 回到上一已知正常版本 | ✅ |
| `jb_list_dir` | 列目录（分页；符号链接不跟随） | ✅ |
| `jb_stat` | 文件/目录元信息（含哈希、链接目标） | ✅ |
| `jb_delete` | 删除文件或空目录；递归须双确认 | ✅ |
| `jb_rename` | 重命名/移动（限同一项目内） | ✅ |
| `jb_search` | 按名称或内容搜索（带行号） | ✅ |
| `jb_read_chunk` | 分块读取（返回整文件哈希） | ✅ |
| `jb_write_chunk` | 分块写入（支持 SHA256 比对，突破 128 KiB 限制） | ✅ |
| `jb_projects` | 查看已配置项目根（只读） | ✅ |
| `jb_list_dir` | 目录列举（dirfd 上 `os.listdir`，lstat 元数据，不跟随符号链接） | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_stat` | lstat 元数据 + 小文件 sha256；符号链接只报告链接目标 | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_delete` | 删文件／符号链接／空目录；递归需 `recursive+confirm`，有界、不跟随链接 | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_rename` | 单项目内 `os.rename`（dir_fd），不建父目录，可选覆盖 | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_search` | 名字 glob 与字面内容搜索（行号 + 有界片段），多项硬上限 | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_read_chunk` | 分片读取（base64 + 整文件 sha256 + eof） | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_write_chunk` | 按偏移分片写入，可选 SHA256 比较并交换、truncate、fsync | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_projects` | 只读列出已配置项目根及其存在性 | ⚠️ 0.3.4 新增，未真机验证 |
| `jb_mkdir` | 在项目根内建目录（`parents` 逐段创建；`mode` 仅 0700..0777） | ⚠️ 0.3.5 新增，未真机验证 |
| `jb_upload_begin` | 开启暂存式分块上传，返回不透明 `upload_id` | ⚠️ 0.3.5 新增，未真机验证 |
| `jb_upload_chunk` | 按偏移写暂存数据（规则同 `jb_write_chunk`） | ⚠️ 0.3.5 新增，未真机验证 |
| `jb_upload_commit` | 校验后用一次 `os.replace` **原子**就位 | ⚠️ 0.3.5 新增，未真机验证 |
| `jb_upload_abort` | 丢弃暂存并作废 `upload_id`（幂等） | ⚠️ 0.3.5 新增，未真机验证 |

## 安全边界（务必阅读）

- `jb_exec` 是**用户明确授权的 mobile 权限任意 Shell，不是沙箱**，能访问 mobile 有权访问的一切，
  包括主动读取上述 token。
- 本包**不提供 root helper、不做免密 sudo**；需要 root 时由你在越狱终端手动执行一次。
- 文件接口（含 0.3.4 新增的 8 个工具）限定在配置的项目根目录内，默认：
  `/var/mobile/Documents/OpenMinis-Jailbreak`
  越界路径（例如写到 `Documents/` 下其它目录）会被拒绝，这是设计限制而非故障；
  需要时用 `jb_exec`，或把目录加入项目白名单。
- 上游内容（网页、文档、命令输出）可能带来提示注入，诱导执行破坏性命令。
- SHA256 与语法检查只保证**完整性／可解析性**，不等于安全审计。

## 卸载

在 Sileo 中移除即可。卸载会停止服务并清理本包自身的运行文件、服务配置、状态目录与 token
（项目目录为空时一并删除）；**保留**普通项目文件、私人备份以及 Python／Roothide 等依赖。

卸载后可直接重新安装，**不需要先执行 purge**（0.3.3 起放宽：仅当 dpkg 记录为“已安装”时才拒绝覆盖）。

## 原地升级（0.3.6 起）

**不再需要先卸载。** 在 Sileo 里直接更新本包即可，升级过程不会清空 token、配置、审计记录、
已下发的版本目录或任何用户数据：升级完成后 OpenMinis 侧仍用**原有 token** 连接，
不需要重新填 MCP 配置。

升级顺序与保证：

1. `preinst upgrade`（此时旧运行时仍在原位）：完整预检（root、dpkg 架构 `iphoneos-arm64e`、
   Roothide 根映射、mobile 身份与组），校验已安装的 `launcher.py` / `maintenance_runtime.py` /
   `bridge.py` / `mobile_setup.py` 是否命中**已知良好白名单**（0.3.3-1、0.3.5-1 与本版），
   校验 plist 形状，然后把旧运行时、plist 与移动端 active 指针快照进
   `/usr/local/lib/openminis-jb-transaction`（root 所有、0700，并记录 boot id），最后有界停止服务
   并确认端口已释放。**任何一步失败都在改动前中止**，且服务会被重新拉起。
2. `postinst configure`（新文件已就位）：确保 plist 与 root 运行时为本包版本；以 UID501 把打包的
   `bridge.py` 作为新版本入 `versions-v030/` 并原子切换 active 指针（`previous` = 旧 active，
   `jb_rollback` 仍然可用），随后启动服务并做认证健康检查。
3. 成功即提交；升级前的运行时、plist 与 active 指针**不再被直接丢弃**，而是保留到
   `/usr/local/lib/openminis-jb-previous`（root 所有、0700，见下节），随后删除 in-flight 快照；
   失败则按快照回滚旧运行时、旧 plist 与旧 active 指针，重启旧版本，并以非零状态退出
   （dpkg 能正常收尾，不会留下“无法继续”的包状态）。
4. 若 dpkg 在 `preinst` 与 `postinst` 之间中断（最常见的是**载荷解包失败**），dpkg 会调用本版本的
   `postrm abort-upgrade <旧版本号>`：该路径只用同一 boot 的未提交快照把 root 运行时、plist 还原为
   逐字节一致并恢复移动端 active 指针，重启服务并做健康检查，只打印**一行**结论；任何疑问都只打印
   一行 NOTICE 并以 0 退出，绝不会让 dpkg 卡住。token / config / audit 一律不碰。

升级前后都会以 UID501 只读指纹核对 token / config / audit 未被改动；本包在任何阶段都不写、不读
token 明文，也不在 root 身份下导入或执行移动端代码。

说明：本版（0.3.7）只改 control 脚本，`launcher.py` / `maintenance_runtime.py` / `bridge.py` /
`mobile_setup.py` 与 0.3.6 逐字节相同，因此已安装的 0.3.6 会命中“本版打包集合”而通过白名单；
白名单中的历史版本仍为 0.3.3-1 与 0.3.5-1。

不支持原地升级的旧版本（例如 0.3.2 系列）仍按老规矩处理：先卸载再安装。

## 恢复到上一个运行时（0.3.7 起）

### 情况一：升级在解包阶段失败（dpkg 调用 `postrm abort-upgrade`）

现象：`dpkg -i` / Sileo 报解包失败并返回非零；`dpkg -l` 仍显示**旧版本**；`/usr/local/lib/openminis-jb/`
里可能有缺失或被截断的文件（本包自带的 `OpenMinis-Jailbreak_0.3.7-ABORT-TEST.deb` 就是用来复现
这种情况的测试包，见 `ABORT_TEST_0371.md`）。

本包会自动处理，**不需要用户做任何事**：

- 只用未提交、同 boot 的快照与它的 manifest（不读取解包结果）把 4 个 root 运行时文件与 plist
  逐字节还原（写盘前先逐个校验 sha256），再恢复移动端 active 指针；
- 重启服务并做认证健康检查，然后打印**一行**结论，例如
  `OpenMinis-Jailbreak: dpkg aborted the upgrade after preinst; ... the previous version is running and healthy ...`；
- 若无快照、快照已提交、属于其它 boot、或结构/哈希不可信：只打印一行 NOTICE，什么都不改，退出 0；
- 幂等、绝不修改 token / config / audit，也绝不让 dpkg 卡住。快照会留在
  `/usr/local/lib/openminis-jb-transaction` 供复查（不会被这次 abort 删除）。

验证与收尾：

```
dpkg-query -W -f='${Package} ${Version} ${Status}\n' app.openminis.jailbreak   # 仍应是旧版本
shasum -a 256 /usr/local/lib/openminis-jb/*.py                                 # 4 个文件应齐全
launchctl print system/app.openminis.jbbridge | head                            # 服务应已注册
# 之后可以直接重试安装正式包（残留快照会被安全地校验并替换）
dpkg -i /var/mobile/OpenMinis-Jailbreak_0.3.7-1+experimental_iphoneos-arm64e.deb
```

### 情况二：升级“成功”了，但新版本表现不对

一次**成功**的升级会把升级前的已知良好状态保留在：

```
/usr/local/lib/openminis-jb-previous/          # root 所有，0700
├── meta.json                                  # schema、from/to 版本、boot id、全部哈希、旧 active 指针
├── runtime/{launcher,maintenance_runtime,bridge,mobile_setup}.py    # 0600
└── plist                                      # 0600，旧服务 plist 的逐字节副本
```

root 恢复助手（随包安装，`0755`）：

```
/usr/local/bin/openminis-jb-restore-runtime [--dry-run] [--pointer-only]
```

- 先读 manifest 并逐个校验 sha256，再还原 4 个 root 运行时文件、服务 plist 与移动端 active 指针；
  然后重启服务、做认证健康检查，并逐条打印它做了什么；
- `--dry-run` 只校验并打印将要做什么，不落任何字节、不碰 launchd；
- `--pointer-only` 只还原移动端 active 指针（不动 root 运行时与 plist，也不影响 dpkg 记录）；
- manifest 缺失/损坏/未知 schema、被替换成 0755 或符号链接、快照与 manifest 不一致、或保留的 plist
  形状不符合预期时：拒绝执行（退出 1）并说明原因，不落任何字节；
- 幂等；**不读取也不打印 token**，不写 token / config / audit；in-flight 快照
  （`/usr/local/lib/openminis-jb-transaction`）只会被提示存在，绝不会被读取、修改或删除。

推荐的恢复步骤：

```
# 1. 先看会发生什么（不改动任何东西）
/usr/local/bin/openminis-jb-restore-runtime --dry-run
# 2. 只把服务指回上一个运行时（不动 root 运行时/plist，最保守）
/usr/local/bin/openminis-jb-restore-runtime --pointer-only
# 3. 完整的运行时回退（root 运行时 + plist + active 指针 + 重启 + 健康检查）
/usr/local/bin/openminis-jb-restore-runtime
# 4. 需要彻底回到打包版本时，重装本 .deb（推荐路径，见下）
dpkg -i /var/mobile/OpenMinis-Jailbreak_0.3.7-1+experimental_iphoneos-arm64e.deb
```

**必须如实说明的限制**：这个助手恢复的是**设备上的运行时**，而 dpkg 仍然记录**更新的包版本**
（因为它的文件确实已经安装成功）。因此：

- **不推荐**通过安装更旧的 `.deb` 来回退版本号：`dpkg` 会认为是降级，而旧包的运行时白名单
  不可能认识新版本的哈希，`preinst` 会在改动前直接拒绝（这正是本次要修第二个风险的起因）；
- 也不要用 `dpkg --force-downgrade` 去绕开它：那会跳过白名单与 plist 校验。
- 正确做法是按上面的步骤用助手回到旧运行时，然后**重装当前（或更新）的正式包**——
  重装等于做一次正常的原地升级，token / 配置 / 审计都不会丢。

### 保留区与 in-flight 事务的区别

- `/usr/local/lib/openminis-jb-transaction`（0700）：**一次升级进行中**的快照，包含 boot id、
  `committed` 标记与移动端指纹；只在 `preinst`→`postinst` 之间存在，成功即删除（或标记 `committed`）。
- `/usr/local/lib/openminis-jb-previous`（0700）：**已经成功**的升级保留下来的“上一个已知良好状态”，
  只有 manifest（不含 token/config/audit 指纹）；第二次成功升级会用更新的内容整体替换它。
- 两侧互不读写：abort 路径只用 transaction，恢复助手只用 previous；卸载时只删除 manifest 校验通过的
  previous 目录（校验不通过则保留并告警）。

## 构建

```
python3 build.py                          # 生成 .deb（含 root 恢复助手），并校验 Python 3.9 语法
python3 source_archive.py                 # 生成源码归档并重写 SHA256SUMS
python3 make_abort_test_deb.py            # 仅供真机演练：故意让解包失败的 ABORT-TEST 包（不要发布）
python3 -m unittest -v test_package test_safety
python3 test_supervisor.py                # 约 1 分钟，启动真实子进程
python3 test_api.py
python3 test_upgrade.py                   # 约 2 分钟，模拟完整 dpkg 序列
```

构建为可复现：相同源码连续两次构建字节一致（`cmp` 通过）。
`SHA256SUMS` 只列出正式 `.deb` 与源码归档；`OpenMinis-Jailbreak_0.3.7-ABORT-TEST.deb` 是
**仅供真机演练**的故意损坏包（控制脚本与本版一致、data 包被破坏），永远不进校验和、不发布。

测试套件启动时会自选一个空闲端口，因此**在手机上服务正在运行时也能完整运行**
（iSH 与手机共用 `127.0.0.1`，固定端口会与真实服务冲突）。

## 已知问题与未验证项

1. **安装后完整重启、重新越狱的自动恢复未验证。**
2. 自身更新链路已在真机演练通过（上传/校验/切换/回退/坏版本自动回退）。
3. 文件写入接口**不会创建父目录**：`jb_write_file` / `jb_rename` / `jb_upload_commit` 都要求父目录已存在；
   需要建目录时用 `jb_mkdir`（`parents=true` 逐段创建，`mode` 只接受 0700..0777）。
3. 文件接口不能写入项目根目录之外；这是有意限制。
4. `jb_device_info` 的 `ios` 字段依赖 `/System/Library/CoreServices/SystemVersion.plist`；
   读取失败时该字段为 `null`，`release`（内核版本）仍在，但它**不能用来推断 iOS 版本**。

### 新增（0.3.7）

修掉两个“升级之后无路可走”的残留风险（只改 control 脚本，移动端 payload 与 0.3.6 逐字节相同）：

- **升级在解包阶段失败时的自动恢复**：新增 `postrm abort-upgrade`（与 `abort-install`）处理——
  用未提交、同 boot 的快照把 root 运行时与 plist 逐字节还原（写盘前逐个校验 sha256，只依赖快照
  与其 manifest），恢复移动端 active 指针，重启服务并验证健康；只打印一行结论，任何疑问只打印一行
  NOTICE 并以 0 退出，绝不卡住 dpkg；幂等，且绝不碰 token / config / audit。为此把快照还原拆成
  “先整体校验、后落盘”（`load_snapshot` / `apply_snapshot`），并能在解包已经把文件删掉/截断的情况下
  重建 `usr/local/lib/openminis-jb`。
- **支持的回退通道**：成功升级后不再直接删除旧运行时，而是把升级前的 4 个运行时文件、plist 与
  active 指针保留到 `/usr/local/lib/openminis-jb-previous`（0700，显式 manifest：from/to 版本、
  全部哈希、boot id、旧指针），并新增 root 恢复助手
  `/usr/local/bin/openminis-jb-restore-runtime`（`--dry-run` / `--pointer-only`，校验后还原并重启，
  逐条打印；manifest 损坏或快照不匹配即拒绝；幂等；不读不打印 token，不碰 token/config/audit）。
  该区域与 in-flight 事务严格分离。**如实说明**：助手回到的是旧运行时，dpkg 仍记录新版本，
  因此安装旧 `.deb` 不是推荐路径——推荐用助手回退后重装当前/更新的正式包（详见上文）。

### 新增（0.3.6）

**原地升级**（见上文「原地升级」）：`preinst upgrade` 校验白名单运行时与 plist 形状，
把旧运行时／plist／移动端 active 指针快照进 `openminis-jb-transaction`（含 boot id），
再停止服务并确认端口释放；`postinst configure` 以 UID501 对账移动端版本（需要时原子切换
active 指针并把旧 active 记为 `previous`），启动服务并做认证健康检查，成功即提交。
失败会回滚运行时、plist 与指针并重启旧版本，且以非零状态退出。
移动端 `bridge.py` 版本号提升到 `0.3.6`（功能与 0.3.5 相同，仅用于演练版本切换）；
`launcher.py` 与 `maintenance_runtime.py` 逐字节未变，`mobile_setup.py` 亦未变。
本版**不清理、不重置**任何 token／配置／审计／版本目录。

### 新增（0.3.5）

新增 5 个工具：`jb_mkdir` 与暂存式分块上传四件套（`jb_upload_begin` /
`jb_upload_chunk` / `jb_upload_commit` / `jb_upload_abort`），共 25 个工具，MCP API 仍为 3。

- `jb_mkdir(project, path, parents=false, mode="0700")`：只建**一级**目录（`parents=true` 才逐段创建），
  `path` 必须是项目根内的相对路径，绝对路径、空组件、`.`、`..`、`.bridge-state` 与任何符号链接组件一律拒绝；
  缺父目录且 `parents=false` 直接拒绝；叶子已存在时拒绝并在错误文本里说明是目录／文件／符号链接；
  `mode` 只接受 0700..0777 的八进制字符串（含特权的位一律拒绝），并在收紧的 umask 下创建后用
  `fchmod` 精确设定，结果**不会**超出请求的 mode。
- 暂存数据位于私有状态目录内的 `uploads-v030/`，文件工具按名字与 inode 双重拒绝该目录，因此
  **提交前项目里看不到任何东西**。同时在跑的暂存上传上限 4 个、暂存总量上限 256 MiB；
  进程中途死亡只会留下无用的暂存数据，只由有界的过期清扫（默认 1 小时、每次最多检查 64 项／删除 16 项，
  且只动上传区内形如本版 id 的目录）或显式 `jb_upload_abort` 清除。
- `jb_upload_commit` 是 `jb_write_chunk` 多分片写入的**原子替代**：多分片写入本身不是原子的，
  而 commit 先按 `expected_sha256`（如提供）校验装配结果，再用**一次 `os.replace`**（锚定目标 dirfd）
  让目标名字要么是旧文件、要么是完整新文件，绝无半成品；跨文件系统（EXDEV）时退化为
  在目标目录内写临时文件后 `os.replace`，失败路径必定删除临时文件。目标已存在且 `overwrite!=true`
  时拒绝、目录／符号链接／非 mobile 所有或硬链接的目标一律拒绝、`.bridge-state` 一律拒绝。
  commit 成功或 abort 后该 `upload_id` 即作废，不可复用；被拒绝的 commit 不改动目标、也保留暂存（可重试）。
- 本版仍只改移动端 `bridge.py`＋测试与文档，可经自身更新链路（stage/validate/apply）下发，无需重装；
  `maintenance_runtime.py` 与 `launcher.py` 与 0.3.4 逐字节相同，未变。

### 新增（0.3.4）

新增 8 个文件接口工具（`jb_list_dir` / `jb_stat` / `jb_delete` / `jb_rename` /
`jb_search` / `jb_read_chunk` / `jb_write_chunk` / `jb_projects`），全部只接受项目根内的
相对路径，并复用既有 dirfd + `O_NOFOLLOW` 逐段遍历；`.bridge-state` 与任何项目根本身
对所有新工具不可达，列举与搜索也不暴露状态目录。所有上限（列举分页、递归删除条目数、
搜索文件/字节/匹配/墙钟、分片大小与偏移）均为硬失败，不做静默截断。
`jb_write_chunk` 的多分片写入**不是原子操作**；只有显式提供 `expected_sha256` 时才具备
并发修改保护。本版仅改移动端 `bridge.py`，可经自身更新链路（stage/validate/apply）下发，
无需重装；`maintenance_runtime.py` 与 `launcher.py` 未变。

### 已修复（0.3.4）

- 新增 8 个文件接口（见上表）。
- **`os.listdir(fd)` 在设备 Python 3.9 上会关闭描述符**（3.12 不会）。原先三处调用点在列举
  后复用同一 dirfd，在真机上必然失败；而健康检查只调用两个信息接口、发现不了这种问题。
  现改为经 `dup` 的副本列举，并加了能复现 3.9 语义的回归测试。
- 测试用更大请求体时，服务器回 413 后不排空请求体即关闭连接，客户端可能拿到
  BrokenPipe/Reset 而非状态码；相关断言已覆盖这类连接级拒绝。

### 已修复（0.3.3）

- `jb_process_list` 曾因执行相对命令 `ps` 而失败：守护进程 PATH 不含越狱工具目录，
  而设备上 `ps` 只在 `/rootfs/bin/ps`。现按固定候选顺序探测绝对路径后执行。
- `jb_device_info` 曾只返回内核版本，容易被误当作系统版本；现直接读取系统版本记录。

## 测试

`TEST_REPORT_0371.txt` 记录最近一次完整测试（229 项全部通过，含真实子进程、信号与端口验证，
以及 `test_upgrade.py` 的 56 项原地升级用例：模拟完整 dpkg 序列、失败回滚、跨 boot 快照拒绝、
同版本升级、升级中断恢复 12 项、保留区 6 项、恢复助手 11 项，以及 1 项 0.3.6 载荷等价的白名单固化）。测试在 Linux + Python 3.12 上运行；
Python 3.9 仅做语法解析，不等同真机验收。真机演练请用 `ABORT_TEST_0371.md` 描述的故意损坏包。

## 状态

`0.3.7-1+experimental`（移动端 bridge 仍为 `0.3.6`，MCP API 仍为 `3`）。实验性项目，主要在作者的一台
设备（iPhone15,3 / iOS 16.4.1）上验证，请自行评估风险后再安装。
