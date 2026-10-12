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

## 构建

```
python3 build.py                          # 生成 .deb，并校验 Python 3.9 语法
python3 -m unittest -v test_package test_safety
python3 test_supervisor.py                # 约 2 分钟，启动真实子进程
python3 test_api.py
```

构建为可复现：相同源码连续两次构建字节一致。

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

`TEST_REPORT_0341.txt` 记录最近一次完整测试（141 项全部通过，含真实子进程、信号与端口验证；
其中 `test_filetools.py` 为本版新增的 45 项文件接口用例）。
测试在 Linux + Python 3.12 上运行；Python 3.9 仅做语法解析，不等同真机验收。

## 状态

`0.3.4-1+experimental`。实验性项目，主要在作者的一台设备（iPhone15,3 / iOS 16.4.1）上验证，
请自行评估风险后再安装。
