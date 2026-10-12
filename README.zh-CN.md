# OpenMinis-Jailbreak 0.3.8-1+experimental

以 launchd 服务形式运行、通过本机 MCP 向 OpenMinis 提供越狱侧能力的服务包。
OpenMinis 本体不需要越狱权限、不需要注入、不需要改签名。

完整说明见项目自述文件；本文档随包安装，只记录版本相关信息。

## 本版改动（0.3.8）

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

- 包版本 `0.3.8-1+experimental`；移动端 bridge `0.3.6`；MCP API `3`；工具 25 个。
- 支持从 0.3.3-1、0.3.5-1、0.3.6、0.3.7 原地升级（白名单内置），token 完整保留。
- 更旧的版本（如 0.3.2 系列）仍需先卸载再安装。
- 安装后完整重启并重新越狱的自动恢复已真机验证（jbroot 变化后服务自动恢复）。

## 测试

最近一次完整测试见 `TEST_REPORT_0381.txt`：233 项全部通过（含真实子进程、信号与端口验证，
以及 `test_upgrade.py` 的 56 项原地升级用例）。可复现构建（连续两次构建字节一致）通过。
