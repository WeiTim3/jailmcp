# OpenMinis-Jailbreak

给 [OpenMinis](https://openminis.app) 增加越狱侧能力的本地服务包。它以 launchd 服务形式运行，
作为 MCP 服务器把一组工具暴露在 `127.0.0.1` 上供 OpenMinis 调用。

**OpenMinis 本体不需要越狱权限、不需要注入、不需要改签名** —— 它只做一件普通事：连本机回环端口。

```
OpenMinis（普通沙盒 App）
    │  http://127.0.0.1:18765/mcp  + Bearer 认证
    ▼
launchd → 监督器（root 所有，以 mobile 身份运行）
    ▼
bridge.py（UID 501，api 3）
    ├── 文件读 / 写 / 编辑 / 搜索 / 上传
    ├── 执行 mobile 权限命令
    ├── 设备与系统信息
    └── 自身更新与回退
```

## 环境要求

- Dopamine Roothide（rootless）越狱，iOS 16.x（实测环境 iPhone15,3 / iOS 16.4.1）
- 越狱侧 Python 3.9

## 安装

1. 下载 `dist/` 下的 `.deb`，用 Filza 打开安装，或在支持本地 DEB 的 Sileo 中安装；
2. 在 OpenMinis 里添加 MCP 服务器：

| 字段 | 值 |
|---|---|
| 名称 | `openminis-jb`（任意） |
| 传输 | HTTP |
| URL | `http://127.0.0.1:18765/mcp` |
| 请求头 | `Authorization` = `Bearer <本机 token>` |
| 授权 | None |

token 位于设备上（私密数据，不要提交或分享）：

```
/var/mobile/Documents/OpenMinis-Jailbreak/.bridge-state/token
```

安装后无需重启；卸载后可直接重装，**不需要先 purge**。

## 工具一览（25）

### 信息

| 工具 | 作用 |
|---|---|
| `jb_device_info` | 机型、**真实 iOS 版本**、内核、UID/PID、bridge 版本与源码哈希 |
| `jb_process_list` | 真实系统进程列表 |
| `jb_maintenance_info` | 包版本、API 版本、active/previous 指针、监督器状态 |
| `jb_projects` | 列出已配置的项目根 |

### 文件

| 工具 | 作用 |
|---|---|
| `jb_read_file` / `jb_write_file` | 读写整个文件（Base64；写入可带 SHA256 前置校验） |
| `jb_edit_file` | 精确替换（强制 SHA256 前置校验） |
| `jb_read_chunk` / `jb_write_chunk` | 分块读写，突破 128 KiB 单文件上限 |
| `jb_list_dir` | 列目录（分页；不跟随符号链接） |
| `jb_stat` | 类型、大小、权限、属主、mtime、哈希 |
| `jb_mkdir` | 建目录（可选逐段创建；`mode` 限 0700–0777） |
| `jb_delete` | 删除（递归须 `recursive` + `confirm`） |
| `jb_rename` | 重命名 / 移动（同一项目内） |
| `jb_search` | 按文件名或内容搜索（带行号，多项硬上限） |
| `jb_upload_begin` / `_chunk` / `_commit` / `_abort` | **暂存式分块上传**，提交用单次 `os.replace` 原子就位 |

### 执行与更新

| 工具 | 作用 |
|---|---|
| `jb_exec` | 以 mobile（UID 501）身份执行命令 |
| `jb_restart` | 远程重启服务 |
| `jb_stage_update` / `jb_validate_update` | 上传候选 bridge，校验哈希与语法 |
| `jb_apply_update` | 切换 active 指针；健康检查失败自动回退 |
| `jb_rollback` | 回到上一个已知正常版本 |

## 安全边界（务必阅读）

- `jb_exec` 是**你明确授权的 mobile 权限任意 Shell，不是沙箱**，能访问 mobile 有权访问的一切，
  包括主动读取上面的 token。
- 本包**不提供 root helper、不做免密 sudo**；需要 root 时由你在越狱终端手动执行一次。
- 文件类工具只能访问项目根之内，默认 `/var/mobile/Documents/OpenMinis-Jailbreak`；
  `.bridge-state` 与 `..` 对所有工具不可达。越界拒绝是**设计限制**，需要时用 `jb_exec`。
- 服务只绑回环、强制 Bearer 认证并校验 Host/Origin；升级只在已知哈希白名单内放行，
  **先校验后改动**；token 只做加盐指纹，**永不读取、打印或上传**。
- 上游内容（网页、输出）可能带来提示注入；SHA256 与语法检查只保证完整性／可解析性，不等于安全审计。

## 升级与回退

**原地升级（0.3.6 起）**：在 Sileo 里直接更新即可，不必先卸载。升级**不清空** token、配置、
审计与版本目录 —— 完成后 OpenMinis 仍用**原 token** 连接，不需要重填 MCP 配置。

**升级失败自动恢复（0.3.7 起）**：若 dpkg 在 `preinst` 与 `postinst` 之间中断（最常见是载荷解包失败），
`postrm abort-upgrade` 会自动用同 boot 快照还原运行时、plist 与指针并重启服务，只打印一行结论；
任何疑问只提示 NOTICE 且退出 0，**绝不卡住 dpkg**。

**回到上一个运行时（0.3.7 起）**：每次成功升级都会把上一份已知良好状态保留在
`/usr/local/lib/openminis-jb-previous`，用随包安装的助手恢复：

```sh
sudo /usr/local/bin/openminis-jb-restore-runtime --dry-run   # 只看会发生什么
sudo /usr/local/bin/openminis-jb-restore-runtime             # 恢复运行库 + plist + 指针 + 重启 + 健康检查
```

> **限制**：助手恢复的是**设备上的运行时**，dpkg 仍记录更新的版本号。因此**不推荐**安装更旧的
> `.deb` 来回退（旧包白名单不认识新哈希，会拒绝升级）；正确做法是用助手回到旧运行时后，
> 重装当前或更新的正式包。

## 构建与测试

```sh
python3 build.py                 # 生成 .deb，并校验 Python 3.9 语法（可复现：两次构建字节一致）
python3 source_archive.py        # 生成源码归档并重写 SHA256SUMS
python3 -m unittest -v test_package test_safety
python3 test_supervisor.py       # 约 1 分钟，启动真实子进程
python3 test_api.py
python3 test_upgrade.py          # 约 2 分钟，模拟完整 dpkg 序列
```

测试套件自选空闲端口，**手机服务正在运行时也能跑**（iSH 与设备共用 `127.0.0.1`）。
最近一次完整测试见 `TEST_REPORT_0371.txt`（229 项全过）。

## 状态

`0.3.8-1+experimental`（移动端 bridge 仍为 `0.3.6`，MCP API 仍为 `3`）。

核心能力均已在真机验证：全新安装／卸载清理／免 purge 重装／原地升级／升级中断恢复／一键回退／
自身更新链路（含坏版本自动回退）／完整重启并重新越狱后的自动恢复／全部文件接口／命令执行／远程重启，
以及压力边界（万项递归删除、16 MiB 搜索、10 秒搜索超时、4 路并发上传、256 MiB 配额）。
仅 EXDEV 跨卷回退路径尚未在真机触发。

### 已知限制

- **递归删除非原子**：超出 10000 条目预算时，已删除的条目不会恢复；超过 10000 条目的树必须分片删除。
- **`jb_exec` 的子进程每文件上限 256 KiB**（`RLIMIT_FSIZE`）；大文件须走分块写入接口。
- **分块写入/上传每块都对整个文件重算 sha256（O(n²)）**：大文件吞吐随体积下降，256 MiB 上传需数分钟。
- 状态文件必须保持 0600（属主 mobile），否则加载器拒绝。

这是实验性项目，主要在作者一台设备上验证，请自行评估风险后再安装。
