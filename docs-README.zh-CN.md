# OpenMinis-Jailbreak 0.3.2-2+experimental

## 本次窄修订
修复 Roothide 系统 `/private/var`（以及固定 Documents 路径）映射被逐级 `O_NOFOLLOW` 误拒绝的问题。仅 UID501 助手的 Documents 锚点允许系统映射：分别打开固定 `/var/mobile/Documents` 与 `/private/var/mobile/Documents`，校验目录 UID501、设备号与 inode 一致。双别名一致不是对任意用户路径的信任；路径硬编码、不接受调用者输入。项目和 state 后代仍使用 dirfd + `O_NOFOLLOW`，链接仅可被 unlink 而不会递归到目标；root 收据与 plist 保护不放宽。运行时和 mobile_setup 的 canonical 路径逻辑不变。

**安装前必须已 purge 旧包及 config-files 状态。** `preinst install <old-version>` 仍按 clean-install-only 拒绝；仅 remove 留下 rc/config-files 不够，本次不改升级策略。先以目标机 root Python 3.9 运行配套 `openminis-preflight-readonly-v032r2.py`；它只查询包状态、系统路径、服务及 UID501 fresh（含短暂 socket bind/listen），不读取 token、不创建文件、不安装或清理。失败仅打印固定阶段，不输出异常文本。PASS 只代表预检，不代表安装或服务验证。

本包尚未在手机安装验证；不要据此宣称已可用。原 0.3.2-1 DEB 原样保留。

## 发布边界（重要）
这是 **CLEAN-INSTALL ONLY（仅全新安装）** 版本，不是 0.3.0/0.3.1 的原地升级，也不执行自动迁移。`preinst` 在任何变更前拒绝 dpkg upgrade；请先卸载已验证的旧基线，并由用户自行私下备份需要的数据。旧版 migration-backup、下载、DEB、普通项目文件和 MCP 配置不会被本包自动删除。

唯一项目目录是 `/var/mobile/Documents/OpenMinis-Jailbreak`；不会创建或接受 `openminis-jailbreak` 小写 alias。全新安装若发现大写目录、`.bridge-state`、小写目录/alias、同标签服务或其他运行时残留，将拒绝并保留现场。普通文件仅在用户明确完成旧版卸载后由其自行处理。

## 生命周期
- `preinst install`：只做 root 同标签/运行时和 UID501 纯净状态预检；失败不修改。
- `postinst configure`：UID501 创建 canonical 目录、私有 token/state 和固定 launchd 服务，并进行健康检查。
- `prerm remove`：只停止并验证本包同标签服务及其自有子进程；不删 token/state。
- `postrm remove/purge`：依据 root 所有的 `.clean-install-v032` 凭据，只清理本包的 `.bridge-state`（包括 token、配置、版本、审计、锁和临时文件）；不删 canonical 内普通项目文件。缺失文件、重复执行和可选清理失败仅警告，不让脚本失效。无凭据保留数据。token/state 只在最终 remove/purge 路径处理；升级/中止路径绝不清理。清理成功后删除本包凭据与可验证 plist，运行时 payload 由 dpkg 删除。

监督器信号处理只设置 STOP 标志，主循环轮询子进程；退出使用自有 `Popen` 句柄的有界 TERM/KILL，不读取 mobile PID 文件，也不 blanket-kill。移动端内容通过 UID501、目录 fd、`O_NOFOLLOW` 限定；root 不递归删除 mobile 控制路径。服务标签/路径不明确时停止或清理会拒绝。

## 构建与验证
本目录工具离线构建，不连接手机、不执行 root 操作：

```sh
python3 build.py
python3 -m unittest -v test_package test_safety
python3 test_api.py
python3 -m py_compile source-v030/*.py mobile_setup.py package_lifecycle.py removal_helper.py build.py
sha256sum OpenMinis-Jailbreak_0.3.2-2+experimental_iphoneos-arm64e.deb
```

测试在本地 Python 3.12 上运行，并对全部源执行 Python 3.9 AST 语法门禁；目标机为 Python 3.9。需要真机/iOS Roothide、UID501、launchd、端口释放和真实信号生命周期验证，当前明确标为 experimental，不能把离线 mock 结果当真机验证。
