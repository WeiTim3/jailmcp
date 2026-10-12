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

## 工具（26 个）

- **信息**：`jb_device_info`、`jb_process_list`、`jb_maintenance_info`、`jb_projects`
- **文件**：`jb_read_file`、`jb_write_file`、`jb_edit_file`、`jb_list_dir`、`jb_stat`、
  `jb_mkdir`、`jb_delete`、`jb_rename`、`jb_search`、`jb_read_chunk`、`jb_write_chunk`
- **真实文件系统**：`jb_find`（在 `/rootfs` 下按名字搜整机，只读、有界）
- **上传**：`jb_upload_begin` / `jb_upload_chunk` / `jb_upload_commit` / `jb_upload_abort`（原子就位）
- **执行**：`jb_exec`、`jb_restart`
- **更新**：`jb_stage_update`、`jb_validate_update`、`jb_apply_update`、`jb_rollback`

## 真实文件系统（roothide）

在 roothide 设备上，**`/var` 是被重定向的**（指向 jailbreak 自己的那棵树），设备**真实**路径在 `/rootfs` 下：

- 真实用户数据：`/rootfs/private/var/mobile/…`
- `jb_find` 默认搜的就是这棵真实树（`/rootfs/private/var/mobile`），也可指定 `/rootfs` 下任意路径。

文件类工具（`jb_read_file` 等）仍在项目根 `/var/mobile/Documents/OpenMinis-Jailbreak` 内工作；
要读其它真实文件，用 `jb_find` 定位后配合 `jb_exec`（或直接用绝对路径）。

## 安全边界（务必阅读）

- `jb_exec` 是 **mobile 权限任意 Shell，不是沙箱**，能访问 mobile 有权访问的一切。
- 本包**不提供 root helper、不做免密 sudo**；需 root 时由你在越狱终端手动执行。
- 文件工具只能访问项目根 `/var/mobile/Documents/OpenMinis-Jailbreak`；`.bridge-state` 与 `..` 不可达。
- 只绑回环 + Bearer 认证；升级只认**白名单**内已知良好版本，先校验后改动；token 永不读取/打印/上传。

## 升级与回退

- **原地升级**：Sileo 直接更新，token/config/audit 保留，无需重配 MCP。
- **中断自动恢复**：dpkg 解包失败时自动从同 boot 快照还原，绝不卡住 dpkg。
- **一键回退**：`sudo /usr/local/bin/openminis-jb-restore-runtime [--dry-run]`
  （恢复上一份运行时；dpkg 仍记新版本号，装旧 .deb 不推荐）。

## 构建与测试

```sh
python3 build.py            # 生成 .deb（可复现：两次构建字节一致）
python3 test_package.py test_api.py
python3 test_supervisor.py  # 真实子进程
python3 test_upgrade.py     # 模拟完整 dpkg 序列
```

233 项测试全过（见 `TEST_REPORT_0381.txt`）。

## 状态

`0.3.8-1+experimental`（bridge `0.3.6`，API `3`）。核心能力均真机验证：安装/卸载/重装/原地升级/
中断恢复/一键回退/自更新/坏版本回退/重启重越狱恢复/压力边界。仅 EXDEV 跨卷回退未真机触发。

**已知限制**：递归删除非原子（>10000 条目须分片）；`jb_exec` 子进程每文件 256 KiB 上限；
分块写入每块重算整文件哈希（O(n²)）；状态文件须 0600。

实验性项目，请自行评估风险后安装。
