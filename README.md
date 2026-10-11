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

| 工具 | 作用 | 真机验证 |
|---|---|---|
| `jb_device_info` | 内核、机型、UID、PID、版本与源码哈希 | ✅ |
| `jb_maintenance_info` | 权限边界、项目目录、版本、监督器状态 | ✅ |
| `jb_exec` | 以 mobile 身份执行命令 | ✅ |
| `jb_read_file` | 读取项目文件（Base64 + SHA256） | ✅ |
| `jb_write_file` | 原子创建／覆盖，支持 SHA256 比对 | ✅ |
| `jb_edit_file` | 精确替换唯一匹配 | ✅ |
| `jb_restart` | 远程重启服务 | ✅ |
| `jb_stage_update` | 暂存新版 bridge 并校验哈希／语法 | ⚠️ 未真机验证 |
| `jb_validate_update` | 复核暂存版本 | ⚠️ 未真机验证 |
| `jb_apply_update` | 应用更新，健康检查失败自动回退 | ⚠️ 未真机验证 |
| `jb_rollback` | 回到上一已知正常版本 | ⚠️ 未真机验证 |
| `jb_process_list` | 进程列表 | ❌ 已知缺陷：`ps` 路径未解析，见下 |

## 安全边界（务必阅读）

- `jb_exec` 是**用户明确授权的 mobile 权限任意 Shell，不是沙箱**，能访问 mobile 有权访问的一切，
  包括主动读取上述 token。
- 本包**不提供 root helper、不做免密 sudo**；需要 root 时由你在越狱终端手动执行一次。
- 文件接口限定在配置的项目根目录内，默认：
  `/var/mobile/Documents/OpenMinis-Jailbreak`
  越界路径（例如把文件写到 `Documents/` 下其它目录）会被拒绝，这是设计上的限制而非故障。
- 上游内容（网页、文档、命令输出）可能带来提示注入，诱导执行破坏性命令；不要对不可信来源
  的执行请求照单全收。
- SHA256 与语法检查只保证**完整性／可解析性**，不等于安全审计。

## 卸载

在 Sileo 中移除即可。卸载会停止服务并清理本包自身的运行文件、服务配置、状态目录与 token
（项目目录为空时一并删除）；**保留**普通项目文件、私人备份以及 Python／Roothide 等依赖。

卸载后可直接重新安装，**不需要先执行 purge**。

## 构建

```
python3 build.py            # 生成 .deb，并校验 Python 3.9 语法
python3 tests/test_package.py
python3 tests/test_safety.py
python3 tests/test_supervisor.py   # 需要约 2 分钟，会启动真实子进程
```

构建为可复现：相同源码连续两次构建字节一致。

## 已知问题

1. **`jb_process_list` 不可用。** 该接口执行相对命令 `ps`，而后台服务的 `PATH` 为
   `/usr/bin:/bin:/usr/sbin:/sbin`，不含越狱工具目录；在目标设备上 `ps` 仅存在于
   `/rootfs/bin/ps`。修复方式为解析绝对路径后再执行（早期版本曾这样做，0.3.x 改写时丢失）。
   临时替代：用 `jb_exec` 执行 `/rootfs/bin/ps -axo pid,uid,comm`。
2. **`jb_device_info` 不含真实系统版本。** 它只返回 `uname` 的内核版本，不能据此推断 iOS
   版本；应改为读取 `/System/Library/CoreServices/SystemVersion.plist`。
3. **安装后完整重启、重新越狱的自动恢复未验证。**
4. 自身更新链路（`jb_stage_update` 等）仅通过本机进程测试，真机未演练。

## 测试

`TEST_REPORT_0324.txt` 记录了最近一次完整测试（53 项全部通过，含真实子进程与端口验证）。
测试在 Linux + Python 3.12 上运行；Python 3.9 仅做语法解析，不等同真机验收。

## 状态

`0.3.2-4+experimental`。这是实验性项目，仅在作者的一台设备上验证过，请自行评估风险后再安装。
