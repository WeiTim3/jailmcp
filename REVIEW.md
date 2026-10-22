# 项目评审（2026-10）

评审对象：`0.3.12`（bridge `0.3.10`）。本文件保留当时的问题清单与优先级；
已在 `0.3.14`（bridge `0.3.12`）修掉的条目在标题后标注 **已修**。

## P0

1. **`jb_read_chunk` 的 O(n²) 整文件重哈希** — **已修**。
   每读一块都调用 `hash_leaf()` 重算整个文件；256 KiB 分块读 256 MiB 文件约等于 137 GB I/O。
   现在 `sha256` 是 opt-in（`want_sha256=true`），返回体带 `hashed`。
2. **写入把权限改成 0600，且没有 chmod 工具** — **已修**。
   `write_at()` 现在保留既有权限（状态文件仍 0600）；`jb_write_file` / `jb_edit_file` /
   `jb_upload_commit` 支持 `mode`；新增 `jb_chmod` / `jb_copy` / `jb_symlink` / `jb_readlink`。
3. **错误被吞成一句话、且没有日志** — **已修**。
   返回 `{"error":{"code","message","ref"}}`；异常写入私有 `log-v030.jsonl`；
   新增 `jb_log_tail`；认证失败按 10 秒节流记录。
4. **发布链滞后** — 部分修。
   唯一 tag/Release 仍是 `v0.3.8-1`，当前代码是 `0.3.14-14`；
   Release 只有 `.deb`，没有 `SHA256SUMS` 与源码包；release job 重建而不是复用测试产物。
   CI 已改为上传/复用同一份产物并附带校验和；**仍需人工打 tag 并发布**。
5. **CI 漏跑 `test_filetools.py` 与 `test_upgrade.py`，且未在 Python 3.9 验证** — **已修**：
   全部测试进入 CI，并新增 Python 3.9 容器 job。
6. **安全默认值与文档冲突** — 部分修：
   `allow_mobile_shell` 安装时仍为 `true`（保持兼容），但 README 明确说明如何关闭；
   `jb_find` 整机读取能力与 token 的同 UID 可读性已写入安全边界。
   仍未做：`protected_paths` denylist、`RLIMIT_NPROC/AS/CPU`、默认关闭 shell。

## 0.3.14 新增：原生设置面板

`PreferenceLoader` bundle（`prefs/`，arm64）把面板放进 iOS 设置 App：
状态、重启/回退、Shell 开关、项目根增删、复制 token/MCP 地址、错误日志。
直接调 loopback `/mcp` 与 `/ui/api/config`，不经过网页。

## 0.3.14 附：可选网页控制台

`GET /ui` 是一个内嵌的单页设置面板：状态、版本、supervisor、可回退版本、项目根、
错误日志，以及重启/回退、Shell 开关、项目根增删。`jb_ui_url` 产生一次性 120 秒
ticket，换 `HttpOnly` 8 小时会话 cookie；配置写入走 `/ui/api/config`，不新增 MCP
工具。它**不是** OpenMinis 宿主 App 的 Settings 原生页；宿主 App 不能注入。
iOS 系统设置里的原生面板需要单独的 PreferenceLoader bundle（Theos/SDK 编译），
仍未包含。

## P1

7. **文件接口不完整** — 部分已修：增加 chmod/copy/symlink/readlink，写入保留 mode；
   仍缺目录级上传/下载（tar）、mtime/xattr 保留、`jb_read_file` 文本模式、`jb_find` 分页游标。
8. **`jb_exec` 撑不起长任务** — 未修：仍为 60 秒、每流 256 KiB、无后台任务/流式输出；
   子进程写文件仍受 `RLIMIT_FSIZE=256 KiB` 限制。
9. **无 root 能力选配** — 未修（设计取舍）；README 已明确这是能力上限。
10. **可运维性** — 部分已修：错误日志可读；仍缺 `jb_health`、audit 读取、版本目录 GC、
    端口冲突处理、请求饱和时的 503、I/O 超时与运行期看门狗。
11. **MCP 传输层** — 未修：无 `Mcp-Session-Id` / SSE / `Accept` 校验 / `instructions`；
    仍是 HTTP/1.0 每请求短连接。对 OpenMinis 自带客户端可用，对严格客户端不保证。

## P2

12. **文档不一致** — 已修主要项：README 版本/工具数/测试数更新，删除不存在的
    `TEST_REPORT_0381.txt` 引用；新增 `SECURITY.md` 与本文件。
    仍缺：LICENSE（需作者选择）、CHANGELOG、issue/PR 模板、CI badge、兼容性矩阵。
13. **打包** — 未改：`Maintainer` 仍是占位符；无 `Homepage`、`firmware` 依赖、xz 压缩、
    包签名与 apt 软件源（因此“Sileo 直接更新”只在配置了源时成立，README 已改写）。
14. **兼容性** — 未改：仅 roothide + iOS 16 + `iphoneos-arm64e`；
    普通 Dopamine/palera1n/arm64/iOS 17+ 不支持。
15. **可维护性** — 部分：测试已全部进 CI；仍无 ruff/mypy/coverage/fuzz；
    `bridge.py` 仍是单文件密集风格；`test_fixtures/` 仍复制历史 bridge。
