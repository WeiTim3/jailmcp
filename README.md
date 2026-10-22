# OpenMinis-Jailbreak

给 [OpenMinis](https://openminis.app) 增加越狱侧能力的本地服务包：以 launchd 服务形式运行，
作为 MCP 服务器把工具暴露在 `127.0.0.1` 上。**OpenMinis 本体不需越狱、不注入、不改签名**，
只做一件普通事：连本机回环端口。

```
OpenMinis（普通沙盒 App）
    │  http://127.0.0.1:18765/mcp  + Bearer 认证
    ▼
launchd → 监督器（root 所有，mobile 身份）→ bridge.py（UID 501）
    ├── 文件读/写/编辑/搜索/上传
    ├── 执行 mobile 命令
    └── 自身更新与回退
```

## 环境要求

- Dopamine Roothide（rootless）越狱，iOS 16.x（实测 iPhone15,3 / iOS 16.4.1）
- 越狱侧 Python 3.9

## 安装

1. 从 [Release](https://github.com/WeiTim3/openminis-jailbreak/releases) 下载 `.deb`，用 Filza 或 Sileo 安装；
2. 在 OpenMinis 里添加 MCP 服务器：

| 字段 | 值 |
|---|---|
| 名称 | `openminis-jb` |
| 传输 | HTTP |
| URL | `http://127.0.0.1:18765/mcp` |
| 请求头 | `Authorization: Bearer <本机 token>` |

token 位于设备上（私密数据，勿分享）：

```
/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state/token
```

安装后无需重启；卸载后可直接重装，**不必 purge**。

## iOS 设置面板（原生，推荐）

安装后打开“设置”App，根级会出现 **OpenMinis-JB**（PreferenceLoader 加载的
原生 bundle，源码在 `prefs/`）。它不打开网页，也不依赖 OpenMinis 宿主 App：

- 状态：bridge 版本、API、PID/UID、supervisor、可回退版本、source sha256
- 操作：重启 bridge、回退上一版（带确认）
- 能力：`mobile Shell` 开关、项目根的增删（名称 + 绝对路径，后端校验）
- 连接：复制 MCP 地址、复制 token
- 诊断：查看最近 50 条错误日志

面板直接用 loopback HTTP 调 `/mcp` 与 `/ui/api/config`，token 从系统目录或
`.jbroot-*` 目录读取；不经过浏览器，也不需要网页会话。

如果安装后看不到入口：关闭并重新打开“设置”；仍看不到时，在越狱终端执行
`ldid -S /Library/PreferenceBundles/OpenMinisJBPrefs.bundle/OpenMinisJBPrefs`
后重开“设置”。

## 可选：本机网页控制台

除了原生设置面板，bridge 还自带一个可选的网页控制台：

- 在对话里调用 `jb_ui_url`，打开返回的一次性链接（120 秒有效，只能用一次）；
- 或在设备浏览器打开 `http://127.0.0.1:18765/ui`，粘贴 token。

面板显示 bridge 版本、API、PID、supervisor、可回退版本、项目根和错误日志；
可以切换 `mobile Shell`、增删项目根、重启服务、回退上一版。页面完全内嵌、
无外部资源，`/ui` 本身不含任何机密；ticket 在 URL fragment 中，换取
`HttpOnly; SameSite=Strict` 的 8 小时会话 cookie。配置写入只走
`/ui/api/config`，不新增 MCP 工具，因此不扩大模型可调用的工具面。

这是桥自带的面板，**不是 OpenMinis 宿主 App 的原生 Settings 页面**：宿主 App
是签名应用，不能从外部注入页面。iOS 系统设置里的原生面板需要单独的
PreferenceLoader bundle（需要 Theos/SDK 编译），目前还未包含。

## 工具（32 个）

- **信息**：`jb_device_info`、`jb_process_list`、`jb_maintenance_info`、`jb_projects`
- **文件**：`jb_read_file`、`jb_write_file`、`jb_edit_file`、`jb_list_dir`、`jb_stat`、
  `jb_mkdir`、`jb_chmod`、`jb_delete`、`jb_rename`、`jb_copy`、`jb_symlink`、`jb_readlink`、
  `jb_search`、`jb_read_chunk`、`jb_write_chunk`
- **真实文件系统**：`jb_find`（用设备路径搜整机，自动落系统目录；可按**名字/内容**搜、按**大小**过滤，
  返回权限/属主/mtime；只读、有界）
- **上传**：`jb_upload_begin` / `jb_upload_chunk` / `jb_upload_commit` / `jb_upload_abort`（原子就位）
- **执行**：`jb_exec`、`jb_restart`
- **更新**：`jb_stage_update`、`jb_validate_update`、`jb_apply_update`、`jb_rollback`
- **诊断**：`jb_log_tail`、`jb_ui_url`

## 文件权限、分块与错误

- **权限保留**：`jb_write_file` / `jb_edit_file` / `jb_upload_commit` 保留目标文件原有权限位；
  新文件默认 `0600`，需要可执行位时传 `mode="0755"`（也可用 `jb_chmod` 事后修改）。
  符号链接永远不会被当作写入目标。
- **分块是线性的**：`jb_read_chunk` / `jb_write_chunk` / `jb_upload_chunk` 的整文件 sha256
  只在显式 `want_sha256=true`（写路径还有 `final=true`）时计算，返回体用 `hashed` 标明；
  分块读写的成本随文件大小线性增长，而不是平方。
- **结构化错误**：失败时返回
  `{"error": {"code": "ENOENT", "message": "...", "ref": "..."}}`。`code` 是稳定的 errno 风格代码
  （`ENOENT` / `EACCES` / `EINVAL` / `ENOSPC` …），`message` 不回显调用参数；完整异常写入
  `.bridge-state/log-v030.jsonl`（`0600`，256 KiB 上限，原地轮转），用 `jb_log_tail` 按 `ref` 查看。
- **单次上限**：`jb_read_file` / `jb_write_file` 单次 256 KiB；大文件用 `jb_read_chunk` /
  `jb_upload_*`。`jb_copy` 单文件 256 MiB。

## 路径约定：系统目录优先，越狱目录次之

在 roothide 设备上，**同一个路径前缀下有两棵不同的树**：

| 名称 | 路径 | 是什么 |
|---|---|---|
| **系统目录**（第一） | `/rootfs/private/var/mobile/…` | iOS 真实数据卷 |
| **越狱目录**（第二） | `/var/mobile/…` → `/rootfs/private/var/mobile/Containers/Shared/AppGroup/.jbroot-<id>/var/mobile/…` | roothide 的 jbroot |

两者**前缀相同但不是同一目录**（越狱目录嵌套在系统目录的 `Containers/Shared/AppGroup/.jbroot-*/` 下）。
**约定：查找、读取、写入一律以系统目录为先，越狱目录为次。**
`/System/...` 同理 —— 真实系统文件在 `/rootfs/System/...`（如字体 `/rootfs/System/Library/Fonts`）。

- `jb_find` 直接写**设备路径**即可，会自动落到系统目录：
  `/var/mobile/Documents` → `/rootfs/private/var/mobile/Documents`、
  `/System/Library/Fonts` → `/rootfs/System/Library/Fonts`；
  已经是 `/rootfs/…` 的原样使用；加 `jailbreak=true` 则改搜**越狱目录**。
- `jb_maintenance_info` 的 `paths` 字段直接给出这两条根路径（`prefer: "system"`）。
- 文件类工具（`jb_read_file` 等）仍限在项目根内；读其它文件用 `jb_find` 定位后配 `jb_exec`。

## 安全边界（务必阅读）

- `jb_exec` 是 **mobile 权限任意 Shell，不是沙箱**，能访问 mobile 有权访问的一切。
- `jb_find` 以 mobile 身份读取**整机数据卷**（含其它 App 的容器），只读但有内容搜索能力；
  只应在你信任当前对话与模型的前提下使用。
- 同 UID 的未沙盒进程（越狱插件/守护进程）可以读取 token 与状态目录，**token 不是越狱级恶意软件的边界**。
  安装时 `allow_mobile_shell` 默认为 `true`，可在 `.bridge-state/config-v030.json` 改为 `false` 后重启服务。
- 本包**不提供 root helper、不做免密 sudo**；需 root 时由你在越狱终端手动执行。
- 文件工具只能访问项目根 `/var/mobile/Documents/OpenMinis-Jailbreak`；`.bridge-state` 与 `..` 不可达。
- 只绑回环 + Bearer 认证，并校验 `Host`/`Origin` 以防 DNS rebinding；升级只认**白名单**内已知良好版本，
  先校验后改动；token 永不读取/打印/上传。

## 升级与回退

- **原地升级**：用新 `.deb` 覆盖安装（Sileo 配置了本仓库的软件源时可直接更新），
  token/config/audit 保留，无需重配 MCP。
- **中断自动恢复**：dpkg 解包失败时自动从同 boot 快照还原，绝不卡住 dpkg。
- **一键回退**：`sudo /usr/local/bin/openminis-jb-restore-runtime [--dry-run]`
  （恢复上一份运行时；dpkg 仍记新版本号，装旧 .deb 不推荐）。

## 在 GitHub Actions 上构建面板

仓库带 `.github/workflows/prefs.yml`，在 **macos-14** runner 上用 Xcode 的
`clang`/`ld` 编译 arm64e bundle，并打出 `.deb`：

```sh
git push
# GitHub → Actions → prefs → Run workflow
```

产物在 Actions 的 `OpenMinis-Jailbreak-deb` / `OpenMinisJBPrefs-bundle`
Artifacts 里。macOS runner 自带 Xcode 和 iOS SDK，不需要自己准备 clang/ld64。

## 构建与测试

```sh
python3 build.py            # 生成 .deb（可复现：两次构建字节一致）
python3 test_package.py
python3 test_api.py
python3 test_filetools.py   # 文件接口 / 权限 / 错误契约
python3 test_safety.py      # 需要 root 与 UID 501 测试环境
python3 test_supervisor.py  # 真实子进程
python3 test_upgrade.py     # 模拟完整 dpkg 序列
```

仓库内共 257 项测试；CI 在完整测试集之外，额外用 Python 3.9 运行非特权测试。

## 状态

`0.3.14-13+experimental`（bridge `0.3.12`，API `3`）。核心能力均真机验证：安装/卸载/重装/原地升级/
中断恢复/一键回退/自更新/坏版本回退/重启重越狱恢复/压力边界。仅 EXDEV 跨卷回退未真机触发。

**已知限制**：递归删除非原子（>10000 条目须分片）；`jb_exec` 子进程每文件 256 KiB 上限、
最长 60 秒、无后台任务；单次 `jb_write_file` 256 KiB；`jb_copy` 不保留 mtime/xattr。
状态文件须 0600。

实验性项目，请自行评估风险后安装。
