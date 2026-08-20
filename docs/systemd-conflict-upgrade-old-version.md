# fn-netdiag 升级后前端仍旧版 — 手动 systemd 与应用中心冲突

> 2026-08-20
> 现象：应用从 `1.0.2` 升级到 `1.1.0` 后，前端仍显示旧版本 `1.0.2`，卸载重装也不生效

---

## 摘要

fn-netdiag 升级后前端仍显示旧版本，根因是**手动配置的 systemd 服务与 fnOS 应用中心标准生命周期管理（`cmd/main`）冲突**：systemd 旧进程长期占用 `28002` 端口，导致应用中心升级时启动的新版本进程因端口被占而失败，最终由旧进程继续服务，前端停留在旧版本。

> ⚠️ 这是「卸载重装」也无效的典型原因——**卸载只清应用中心管理的进程，不会停用手动 systemd 服务**。重装后 systemd 旧进程仍占端口，新版本仍起不来。

---

## 一、两套管理机制冲突

### 机制 A：fnOS 应用中心标准管理（✅ 正确）

应用自带 `/var/apps/fn-netdiag/cmd/main`，由应用中心调用，支持 start/stop/status/restart：
- 启动时从 manifest **动态读取版本号**（如 1.1.0）传给服务
- 升级时应用中心自动调用 `cmd/main` 以新版本重启

### 机制 B：手动 systemd 服务（❌ 错误，冲突源）

```ini
[Service]
ExecStart=/usr/bin/python3 /vol1/@appcenter/fn-netdiag/server.py
Environment=ENV_PROBE_VERSION=1.0.2   # ← 硬编码旧版本
...
```

- 版本号硬编码 `1.0.2`，不跟随 manifest 更新
- 独立于应用中心，不受升级/卸载管理
- **长期占用 28002 端口**

---

## 二、故障根因

### 时间线（从 app.log 还原）

```
[13:11:07] server failed to start        # Address already in use
[13:26:07] server started (pid 2104512)  # 应用中心升级时启动新版本
[13:26:08] server failed to start        # Address already in use
                                          # └─ 28002 被 systemd 旧进程占用
```

- 应用中心升级 → `cmd/main` 尝试以新版本启动
- 但 `28002` 被手动 systemd 旧进程（1.0.2）占用
- 新进程 bind 失败 → `OSError: Address already in use` → 启动失败
- systemd 旧进程继续运行，前端停留 1.0.2

### 判断要点

| 项 | 说明 |
|----|------|
| 直接原因 | 端口被旧 systemd 进程占用，新版本进程无法启动 |
| 根本原因 | 手动 systemd 与应用中心 `cmd/main` 机制冲突 |
| 版本错位 | systemd 硬编码 `ENV_PROBE_VERSION=1.0.2`，不跟随 manifest |
| 关键佐证 | ① app.log 多次 `Address already in use`；② 进程启动时间早于升级时间；③ manifest 已是 1.1.0 |

---

## 三、排查步骤（可复用）

```bash
# 1. 当前运行进程及其启动时间（判断是否旧进程）
ps -eo pid,lstart,cmd | grep 'fn-netdiag/server.py' | grep -v grep

# 2. 磁盘代码修改时间（判断是否被升级覆盖）
stat -c "%y  %n" /vol1/@appcenter/fn-netdiag/server.py

# 3. manifest 真实版本
grep -E '^version' /var/apps/fn-netdiag/manifest

# 4. 应用中心生命周期日志（找端口冲突）
tail -20 /vol1/@appdata/fn-netdiag/app.log

# 5. 端口占用
ss -tlnp | grep 28002

# 6. 是否存在手动 systemd 服务
systemctl list-units --type=service | grep -i netdiag
```

> **判断要点**：进程启动时间 vs 文件修改时间。若进程启动早于升级时间，则运行旧代码；若 app.log 出现 `Address already in use`，说明新版本进程被端口占用挡住。

---

## 四、解决方案

### 1. 停用手动 systemd 服务（释放端口）

```bash
sudo systemctl disable --now fn-netdiag.service
sudo rm -f /etc/systemd/system/fn-netdiag.service
sudo systemctl daemon-reload

# 确认 28002 已释放
ss -tlnp | grep 28002   # 应无输出
```

### 2. 用应用中心标准脚本启动

```bash
sudo sh -c 'TRIM_APPNAME=fn-netdiag \
  TRIM_APPDEST=/var/apps/fn-netdiag \
  TRIM_PKGVAR=/vol1/@appdata/fn-netdiag \
  /var/apps/fn-netdiag/cmd/main start'
```

> `TRIM_PKGVAR` 必须指向真实数据目录，否则 cmd/main 因默认路径无权限失败。

### 3. 验证

```bash
ss -tlnp | grep 28002                          # 监听中
curl -s http://127.0.0.1:28002/health          # {"ok":true,"version":"1.1.0"}
curl -s http://127.0.0.1:28002/ | grep -oiE "v[0-9]+\.[0-9]+\.[0-9]+"   # v1.1.0
```

---

## 五、经验教训

1. **fnOS 应用若有自带的 `cmd/main` 生命周期脚本，不应再额外配置 systemd 服务。** 应用中心升级/启停会调用 `cmd/main`，手动 systemd 会抢占端口并硬编码旧配置，导致升级无法生效。

2. **「卸载重装」不能清除手动 systemd 服务**——它独立于应用中心。所以 systemd 冲突导致的旧版问题，重装也无效，必须先停用 systemd。

3. **升级不生效的通用排查顺序**：
   - 运行进程的启动时间是否晚于升级时间（若旧进程，升级未重启）
   - `app.log` 是否有 `Address already in use`（端口冲突）
   - manifest 版本 vs 运行版本是否一致
   - 是否有多套进程管理机制并存

4. **确需开机自启**：依赖 fnOS 应用中心的应用策略，而不是另建 systemd 服务。fnOS 对 `is_non_manual_stop=false` 的应用默认开机自启。

---

*文档结束*
