# OpenMinis-Jailbreak 0.3.14-11+experimental

以 launchd 服务形式运行、通过本机 MCP 向 OpenMinis 提供越狱侧能力的服务包。
OpenMinis 本体不需要越狱权限、不需要注入、不需要改签名。

完整说明见项目自述文件；本文档随包安装，只记录版本相关信息。

## 本版改动（0.3.14）

> `0.3.14-10`：动态类 + Theos aarch64 工具链。二进制里没有
> `__objc_classlist`，完全避开 libobjc `readClass`；构造函数只用
> `objc_getClass`，不再在 dyld 初始化阶段发 Objective-C 消息。
> 仍保留 GitHub Actions macOS 构建工作流。

bridge 版本提升到 `0.3.12`：新增 **iOS 设置里的原生面板**（PreferenceLoader
bundle），并保留一个可选的网页控制台。

- **原生设置面板**：安装后“设置”App 根级出现 **OpenMinis-JB**。状态、重启/回退、
  `mobile Shell` 开关、项目根增删、复制 token/MCP 地址、错误日志都在里面；
  直接通过 loopback 调 bridge，不打开网页。源码在 `prefs/`，bundle 在
  `/Library/PreferenceBundles/OpenMinisJBPrefs.bundle`。
- 如果入口不出现：关闭并重开“设置”；仍看不到时，在越狱终端执行
  `ldid -S /Library/PreferenceBundles/OpenMinisJBPrefs.bundle/OpenMinisJBPrefs`
  再重开。
- `GET /ui`（可选网页控制台）：一个自包含的设置面板（HTML/CSS/JS 全部内嵌，无外部资源），
  显示桥状态、版本、PID、supervisor、可回退版本、项目根、错误日志；
  可以切换 mobile Shell、增删项目根、重启服务、回退上一版。
- `jb_ui_url`（第 32 个工具）：返回一个**一次性、120 秒有效**的链接。
  ticket 放在 URL fragment 里，不会被服务端记录；页面用它换一个
  `HttpOnly; SameSite=Strict` 的 8 小时会话 cookie。也可以直接打开
  `http://127.0.0.1:18765/ui` 并粘贴 token。
- 会话是 **HMAC 无状态 cookie**（以 token 为密钥），bridge 重启后仍然有效；
  token 轮换后自动失效。控制台的配置写入只走 `/ui/api/config`，不是 MCP 工具，
  因此不会扩大 agent 能调用的工具面。
- 新增的 `Origin` 允许列表只放行 `http://127.0.0.1:<port>` 与
  `http://localhost:<port>`，其他来源仍然 403。

打包白名单补上 `0.3.13-2` 的运行库集合，因此这台设备可以从 0.3.13-2
原地升到 0.3.14；同时保留 0.3.12 的集合，旧设备也能升级。

## 历史（0.3.13）

> `0.3.13-2` 是打包修订：补上 `0.3.12-1` 的运行库白名单条目。`0.3.13-1` 会在
> `upgrade-runtime-allowlist` 阶段拒绝从 0.3.12 升级（bridge 仍是 `0.3.11`，功能相同）。

bridge 版本提升到 `0.3.11`，修掉三处会直接影响日常使用的问题，并补了四个文件工具。

**1. 分块读取不再重复整文件哈希。** `jb_read_chunk` 过去每读一块都重算整个文件的 sha256，
下载 256 MiB 文件要额外读取约 137 GB。现在 `sha256` 默认是 `null`，只有 `want_sha256=true`
时才计算（返回体新增 `hashed`）；需要校验时在最后一块请求一次即可。

**2. 写入不再把文件权限改成 0600。** `jb_write_file` / `jb_edit_file` / `jb_upload_commit`
现在保留目标文件原有的权限位；新文件默认 0600，可用 `mode="0755"` 显式指定。`jb_upload_commit`
新增 `mode` 参数，上传的脚本不会再丢失可执行位。

**3. 错误可诊断，但不对模型泄露细节。** 工具失败时返回
`{"error": {"code": "ENOENT", "message": "...", "ref": "..."}}`，`code` 是稳定的 errno 风格代码；
完整的异常文本写入私有 `0600` 日志 `.bridge-state/log-v030.jsonl`（256 KiB 上限、原地轮转），
用新工具 `jb_log_tail` 按 `ref` 查看。HTTP 认证失败也会记录（10 秒节流）。

**新增工具（26 → 31）：**

- `jb_chmod`：设置文件/目录权限（`0000`–`0777`，拒绝特权位），不跟随符号链接；
- `jb_copy`：项目内/跨项目复制普通文件，原子落位并保留权限；
- `jb_symlink` / `jb_readlink`：创建和读取符号链接，任何文件工具都不会跟随它；
- `jb_log_tail`：读取最新一段错误日志。

`maintenance_runtime.py` 的 `write_at()` 增加了 `mode` / `preserve` 参数（状态文件仍固定 0600）；
`launcher.py` / `mobile_setup.py` 未变。

## 历史（0.3.12）

**消除分块写入/上传的 O(n²) 整文件重算哈希**（bridge 版本提升到 `0.3.10`）。此前每写一块都会重算**整个文件**的
sha256 —— 256 MiB 分 1024 块约等于读取 137 GB，吞吐随体积单调衰减。

现在整文件摘要**只在 `final=true`（或显式 `want_sha256=true`）时计算**，其余块只做一次 fstat 取大小：返回体新增
`hashed` 字段，`sha256` 未计算时为 `null`。CAS（`expected_sha256`）语义不变（它本来就在写前校验）。

真机实测（分块上传，256 KiB/块）：32 → 128 MiB 每个窗口都稳定在 **~2.97 MiB/s**（修复前 1.62 → 0.23 MiB/s 单调衰减）；
外推 256 MiB 约 **85 秒**（修复前约 7 分钟）。

`launcher.py` / `maintenance_runtime.py` / `mobile_setup.py` 未变，只有 `bridge.py` 变了；升级白名单已含 0.3.11 那套运行库。

## 历史（0.3.11）

`jb_find` 增强（bridge 版本提升到 `0.3.9`）。除了按名字搜，现在还能：

- **按内容搜**：`content="..."` 在文件内查找，返回 1 起始行号与有界摘录，受 `max_file_bytes` 约束；
- **按大小过滤**：`min_bytes` / `max_bytes` —— 只作用于普通文件；带大小条件时不再列出目录；
- **元信息**：每个匹配返回 `mode` / `uid` / `gid` / `mtime`（另有 `size`、`name_match`、`line`、`excerpt`）。

仍为只读、有界（墙钟 / 条目数 / 深度 / 匹配数 / 单文件字节），符号链接目录只报告不进入。

`launcher.py` / `maintenance_runtime.py` / `mobile_setup.py` 未变，只有 `bridge.py` 变了；升级白名单已含 0.3.10 那套运行库。

## 历史（0.3.10）

`jb_find` 现在**直接接受设备路径**，自动映射到系统目录（bridge 版本提升到 `0.3.8`）：

| 你写 | 实际搜索 |
|---|---|
| `/var/mobile/Documents`（默认 `/var/mobile`） | `/rootfs/private/var/mobile/Documents` |
| `/System/Library/Fonts` | `/rootfs/System/Library/Fonts` |
| 已是 `/rootfs/…` | 原样使用 |

加 `jailbreak=true` 改为搜索越狱目录（jbroot）。`jb_maintenance_info` 的 `paths` 字段给出两条根路径与 `prefer: "system"`。

`launcher.py` / `maintenance_runtime.py` / `mobile_setup.py` 未变，只有 `bridge.py` 变了；升级白名单已含 0.3.9 那套运行库。

## 历史（0.3.9）

新增工具 **`jb_find`**（bridge 版本提升到 `0.3.7`）：在**真实设备文件系统**（`/rootfs` 下）按名字递归搜索，
默认从 `/rootfs/private/var/mobile` 开始。只读、有界（墙钟 / 条目数 / 深度），不进入符号链接目录。

背景：roothide 设备上 `/var` 被重定向到 jailbreak 自己的树，设备真实数据在 `/rootfs/private/var/…`；
此前只能看到重定向那棵，所以会"搜不到"某些文件（如 DumpDecrypter 的 ipa）。

**路径约定（系统目录优先）**：同一路径前缀下有两棵树——**系统目录** `/rootfs/private/var/mobile/…`
（iOS 真实数据卷）与**越狱目录** `/var/mobile/…`（roothide 重定向，落在 jbroot 内）。
约定：查找、读取、写入**一律以系统目录为先，越狱目录为次**。
`jb_maintenance_info` 新增 `paths` 字段直接给出这两条根路径（`prefer: "system"`），
`jb_find` 默认也搜系统目录。

`launcher.py` / `maintenance_runtime.py` / `mobile_setup.py` 与 0.3.6 逐字节相同，**只有 `bridge.py` 变了**，
因此升级白名单新增了 0.3.6 运行库集合（`KNOWN_SETS['0.3.6-1']`）；0.3.6 / 0.3.7 / 0.3.8 均可原地升级。

## 历史（0.3.8）

只改 control 脚本（运行时四件与 0.3.7 / 0.3.6 **逐字节相同**）。修掉一个真机缺陷：

**过期快照不再阻塞全新安装**：干净安装守卫此前只要 `/usr/local/lib/openminis-jb-transaction`
存在就拒绝，而卸载又故意保留该快照供复查——两者叠加，导致「卸载 → 重装」在经历过一次中断升级后
永久卡死（`preinst-root-residue`）。现在只有**同一次开机、未提交**的快照（即真正进行中的升级）
才拒绝；跨开机、已提交、或结构不可读的快照都不可能用于恢复，只打印一行 NOTICE 并放行。

## 历史（0.3.7）

只修改 control 脚本 —— `launcher.py` / `maintenance_runtime.py` / `bridge.py` /
`mobile_setup.py` 与 0.3.6 **逐字节相同**。修掉两个「升级之后无路可走」的残留风险：

1. **升级在解包阶段中断时的自动恢复**
   dpkg 在 `preinst` 之后、`postinst` 之前失败（最常见是载荷解包失败）时会调用本版本的
   `postrm abort-upgrade <旧版本号>`。该路径现在会：只用**未提交、同一 boot** 的快照与其 manifest
   （不读取解包结果）把 4 个 root 运行时文件与 plist **逐字节**还原——先整体校验、每个文件写盘前
   再校验 sha256——随后恢复移动端 active 指针、重启服务并做认证健康检查，只打印**一行**结论。
   无快照 / 已提交 / 跨 boot / 结构或哈希不可信时，只打印一行 NOTICE、什么都不改、退出码 0，
   **绝不卡住 dpkg**。幂等；绝不读写或打印 token，绝不碰 config / audit。

2. **一键回到上一个运行时**
   成功升级不再直接丢弃旧运行时，而是把升级前的 4 个运行时文件、服务 plist 与移动端 active 指针
   保留到 `/usr/local/lib/openminis-jb-previous`（root 所有、0700，含显式 manifest：from/to 版本、
   全部哈希、boot id、旧 active 指针），并安装 root 恢复助手：

   ```sh
   sudo /usr/local/bin/openminis-jb-restore-runtime [--dry-run] [--pointer-only]
   ```

   先校验 manifest 与每个 sha256，再还原运行库、plist 与指针，重启服务并验证健康，逐条打印所做操作；
   `--dry-run` 不落任何字节；manifest 损坏、快照不匹配或 plist 形状异常时拒绝执行并退出 1。
   幂等；不读写 token / config / audit；in-flight 事务快照只会被提示存在，绝不读取或删除。

   **如实说明的限制**：助手恢复的是设备上的运行时，dpkg 仍记录**更新的**包版本，因此安装更旧的
   `.deb` 不是推荐路径（旧包的白名单不认识新哈希，会在改动前拒绝）。正规做法是用助手回到旧运行时，
   然后重装当前或更新的正式包——等价于一次正常的原地升级，token／配置／审计都不会丢。

## 版本与兼容

- 包版本 `0.3.14-10+experimental`；移动端 bridge `0.3.12`；MCP API `3`；工具 32 个。
- 支持从 0.3.3-1 到 0.3.14-8 的已发布运行时原地升级（白名单内置），token 完整保留。
- 更旧的版本（如 0.3.2 系列）仍需先卸载再安装。
- 安装后完整重启并重新越狱的自动恢复已真机验证（jbroot 变化后服务自动恢复）。

## 测试

完整测试集 257 项全部通过（含真实子进程、信号与端口验证，以及 `test_upgrade.py` 的
58 项升级用例）。可复现构建（连续两次构建字节一致）由 CI 校验。
