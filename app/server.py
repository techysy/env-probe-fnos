#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fn-netdiag — fnOS 网络诊断 (零依赖 stdlib http.server)

在任意环境打开本应用，展示当前访问环境的完整请求特征：
  - 请求头 (Host / User-Agent / Origin / Referer / X-Forwarded-* / X-Real-IP ...)
  - 来源 IP
  - 环境判断 (桌面浏览器 / 飞牛 iOS App 移动容器 / FN Connect 域名 / 局域网直连)
用于判断移动容器访问时的域名/Host，辅助配置 dsh 信任域。

监听端口: ENV_PROBE_PORT (默认 28002)
"""
import json
import os
import platform
import socket
import ssl
import http.server
import socketserver
import subprocess
import urllib.parse

PORT = int(os.environ.get("ENV_PROBE_PORT", "28002"))
APP_VERSION = os.environ.get("ENV_PROBE_VERSION", "dev")

BRAND = "#22c55e"  # 绿色主题

def _default_data_dir():
    script = os.path.abspath(__file__)
    parts = script.split(os.sep)
    if "@appcenter" in parts:
        idx = parts.index("@appcenter")
        if idx + 1 < len(parts):
            vol = os.sep.join(parts[:idx])
            app = parts[idx + 1]
            if vol and app:
                return os.path.join(vol, "@appdata", app)
    d = os.path.dirname(script)
    for _ in range(4):
        if os.path.basename(os.path.dirname(d)) == "@appdata":
            return os.path.dirname(d)
        d = os.path.dirname(d)
    return os.path.join(os.path.dirname(script), "@appdata")

DATA_DIR = os.environ.get("ENV_PROBE_DATA_DIR") or _default_data_dir()

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LAN_IP = get_lan_ip()

# ── 环境判断 ──────────────────────────────────────────────
# 移动容器判定不再依赖写死的固定域名 (office.app.5ddd.com 曾为猜测值, 实测不可靠/已废弃).
# 改为基于 UA 特征 + FN Connect 域名 (fnos.net) 动态判断: 移动 App 内嵌 webview 通过
# FN Connect 子域名访问时, Host 是每个用户/设备不同的, 不能靠写死的域名匹配.
def detect_environment(headers, host, client_ip):
    """根据请求头判断访问环境"""
    ua = headers.get("user-agent", "")
    ua_l = ua.lower()
    host_l = (host or "").lower()
    verdicts = []
    env = {"kind": "unknown", "label": "未知环境", "mobile_container": False, "fn_domain": False,
           "mobile_url": ""}

    # 0. 是否 FN Connect 域名 (移动 App / 外网访问通常经此)
    is_fn_domain = host_l.endswith(".fnos.net") or host_l == "fnos.net"
    if is_fn_domain:
        env["fn_domain"] = True
        env["label"] = "FN Connect 域名"
        verdicts.append(f"FN Connect 域名: {host}")

    # 1. 移动容器 / 飞牛移动 App (UA 特征 + 移动端)
    mobile_ua_marks = [
        ("fnos", "飞牛 fnOS"),
        ("fnconnect", "FN Connect"),
        ("fnnas", "飞牛 fnOS"),
        ("lark", "飞书"),
        ("feishu", "飞书"),
    ]
    mobile_found = []
    for mark, name in mobile_ua_marks:
        if mark in ua_l:
            mobile_found.append(name)
    if "mobile" in ua_l or "iphone" in ua_l or "ipad" in ua_l or "android" in ua_l or "cfnetwork" in ua_l:
        mobile_found.append("移动端 webview")

    # 移动容器 = 飞牛 App 内嵌 webview 特征 (UA 含飞牛/移动端) 或经 FN Connect 域名访问
    is_mobile_ua = bool(mobile_found)
    if is_mobile_ua or (is_fn_domain and client_ip not in ("127.0.0.1", "::1")):
        env["mobile_container"] = True
        env["kind"] = "mobile-container" if is_mobile_ua else "mobile"
        env["label"] = f"移动容器 (飞牛 App 内嵌 webview)" if is_mobile_ua else f"移动端"
        if is_mobile_ua:
            verdicts.append(f"移动端 UA: {'+'.join(set(mobile_found))}")
        # 完整访问地址 (动态 Host, 不写死域名)
        proto = "https" if headers.get("x-forwarded-proto", "") == "https" else "http"
        env["mobile_url"] = f"{proto}://{host}/"
        verdicts.append(f"移动容器访问地址: {env['mobile_url']}")
        verdicts.append("→ 配置 dsh 信任域, 建议加当前访问域名 (FN Connect 子域名, 每个设备不同)")

    # 2. 桌面浏览器 (非移动)
    if not env["mobile_container"]:
        if any(b in ua_l for b in ("chrome", "safari", "firefox", "edge", "webkit", "gecko")):
            env["kind"] = "desktop"
            env["label"] = "桌面浏览器"
            verdicts.append("桌面浏览器")

    # 3. 转发头 (统一网关/FN Connect 反向代理通常带)
    fwd_for = headers.get("x-forwarded-for", "")
    xr_ip = headers.get("x-real-ip", "")
    fwd_host = headers.get("x-forwarded-host", "")
    if fwd_for or xr_ip or fwd_host:
        verdicts.append(f"存在反向代理转发头 (X-Forwarded-For: {fwd_for or '-'} / X-Real-IP: {xr_ip or '-'} / X-Forwarded-Host: {fwd_host or '-'})")

    # 4. 是否局域网 IP
    if env["kind"] == "unknown" and (client_ip.startswith("192.168.") or client_ip.startswith("10.") or client_ip.startswith("172.")):
        env["kind"] = "lan"
        env["label"] = "局域网直连"
        verdicts.append(f"局域网直连 IP: {client_ip}")

    return env, verdicts

def suggest_trusted(host):
    """根据 Host 给出 trusted_hosts.conf 建议"""
    host = (host or "").strip().lower()
    if not host:
        return []
    hostname = host.split(":")[0]
    # FN Connect 域名: 给出当前访问域名 + fnos.net
    if hostname.endswith(".fnos.net") or hostname == "fnos.net":
        return [hostname, "fnos.net"]
    if hostname.startswith("dsh."):
        return [hostname, "fnos.net"]
    # 本机回环/局域网: 直连无需信任域
    if hostname in ("127.0.0.1", "localhost", "::1"):
        return []
    return [hostname]

# ── fnOS 应用列表 + 按应用/URL 诊断 ───────────────────────
def list_apps():
    """枚举 fnOS 已安装应用: /var/apps/<name>/manifest 读 display_name/service_port"""
    import glob
    apps = []
    for manifest_path in glob.glob("/var/apps/*/manifest"):
        name = os.path.basename(os.path.dirname(manifest_path))
        display, port, desc = name, "", ""
        try:
            for line in open(manifest_path, encoding="utf-8", errors="ignore"):
                s = line.strip()
                if s.startswith("display_name") and "=" in s:
                    display = s.split("=", 1)[1].strip().strip("\"'")
                elif s.startswith("service_port") and "=" in s:
                    port = s.split("=", 1)[1].strip()
                elif s.startswith("desc") and "=" in s:
                    desc = s.split("=", 1)[1].strip().strip("\"'")
        except Exception:
            pass
        apps.append({"name": name, "display": display, "port": port, "desc": desc})
    apps.sort(key=lambda a: a["name"])
    return apps

def diagnose_url(url_or_app):
    """输入网址或应用名 → 分析 Host/端口, 给出信任域建议 + 探测可达性"""
    import socket as _socket
    s = (url_or_app or "").strip()
    if not s:
        return {"ok": False, "error": "请输入网址或应用名"}
    # 解析: 去掉 scheme
    hostport = s.split("://")[-1].split("/")[0]
    host = hostport.split(":")[0]
    port = ""
    if ":" in hostport:
        port = hostport.split(":")[1]
    # 默认端口推断
    proto = "https" if s.startswith("https://") else ("http" if s.startswith("http://") else "")
    if not port:
        port = "443" if proto == "https" else "80"
    # DNS 解析
    dns = resolve_dns(host)
    # 可达性
    reach = None
    try:
        with _socket.create_connection((host, int(port)), timeout=3):
            reach = True
    except Exception as e:
        reach = {"ok": False, "err": str(e)[:60]}
    trusted = suggest_trusted(host)
    return {
        "ok": True, "input": s, "host": host, "port": port, "proto": proto,
        "dns": dns, "reachable": reach, "trusted": trusted,
    }

# ── 容器信息 (docker) ─────────────────────────────────────
def get_containers():
    """读取 Docker 容器列表 (名称/镜像/状态/端口/IP)
    多路径尝试: docker → sudo -n docker; 无容器/权限不足时优雅降级"""
    # 尝试路径
    candidates = [
        ["docker", "ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"],
        ["sudo", "-n", "docker", "ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"],
    ]
    for cmd in candidates:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            continue
        except Exception:
            continue
        if out.returncode == 0:
            rows = []
            for line in out.stdout.strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    rows.append({"name": parts[0], "image": parts[1], "status": parts[2], "ports": parts[3]})
            return {"ok": True, "containers": rows, "count": len(rows)}
        # sudo 失败 / 权限不足, 尝试下一条
        continue
    # 全部失败: 判断是否 docker 不可用还是无权限
    if not _docker_exists():
        return {"ok": False, "available": False, "error": "docker 不可用", "containers": []}
    return {"ok": False, "available": True, "error": "无法访问 docker (权限不足)", "containers": []}

def _docker_exists():
    try:
        subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return True

# ── HTTP 服务 ─────────────────────────────────────────────
# 连通性探测: TCP 连通性 + 延迟 (本机服务 + 局域网服务 + 外网)
def _probe_one(name, host, port):
    import socket
    import time
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=3):
            ms = int((time.time() - t0) * 1000)
            return {"name": name, "host": host, "port": port, "ok": True, "ms": ms}
    except Exception as e:
        return {"name": name, "host": host, "port": port, "ok": False, "ms": None,
                "err": str(e)[:50]}


def _lan_gateway():
    """从本机路由表提取默认网关 IP (Linux /proc/net/route)."""
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
                    gw = int(parts[2], 16)
                    return f"{(gw >> 0) & 0xFF}.{(gw >> 8) & 0xFF}.{(gw >> 16) & 0xFF}.{(gw >> 24) & 0xFF}"
    except OSError:
        pass
    return None


def probe_connectivity():
    """本机 + 局域网 + 外网连通性探测.

    - 本机 (127.0.0.1): dsh / 9Router / mihomo
    - 局域网 (LAN_IP): 同端口, 验证局域网 IP 上的服务可被其他设备访问; 网关连通性
    - 外网: GitHub / DeepSeek / FN Connect
    """
    import socket
    # 本机服务 (回环)
    local_targets = [
        ("dsh", "127.0.0.1", 28000),
        ("9Router", "127.0.0.1", 20128),
        ("mihomo", "127.0.0.1", 9090),
    ]
    # 局域网服务 (LAN_IP, 验证可被局域网内其他设备访问)
    lan_targets = []
    lan_ip = get_lan_ip()
    if lan_ip != "127.0.0.1":
        for name, _, port in local_targets:
            lan_targets.append((f"{name} (局域网)", lan_ip, port))
    # 网关连通性
    gw = _lan_gateway()
    if gw:
        lan_targets.append(("网关", gw, 443))
    # 外网
    wan_targets = [
        ("GitHub API", "api.github.com", 443),
        ("DeepSeek API", "api.deepseek.com", 443),
        ("FN Connect", "fnos.net", 443),
    ]

    results = []
    for name, host, port in local_targets + lan_targets + wan_targets:
        results.append(_probe_one(name, host, port))
    return results

# DNS 解析: 当前访问域名解析到哪些 IP
def resolve_dns(host):
    import socket
    hostname = (host or "").split(":")[0]
    if not hostname:
        return {"host": host or "", "error": "empty host"}
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = sorted(set(i[4][0] for i in infos))
        return {"host": hostname, "ips": ips, "count": len(ips)}
    except Exception as e:
        return {"host": hostname, "error": str(e)}

# 历史快照: 每次探测保存到 DATA_DIR/history.jsonl
def save_history(entry):
    import json as _json
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        hist_path = os.path.join(DATA_DIR, "history.jsonl")
        with open(hist_path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def load_history(limit=20):
    import json as _json
    try:
        hist_path = os.path.join(DATA_DIR, "history.jsonl")
        if not os.path.isfile(hist_path):
            return []
        lines = open(hist_path, encoding="utf-8").read().strip().splitlines()
        return [_json.loads(x) for x in lines[-limit:]][::-1]
    except Exception:
        return []

PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fnOS 网络诊断</title>
<style>
:root{--brand:{{BRAND}};--bg:#f1f5f9;--card:#ffffff;--fg:#0f172a;--muted:#64748b;--ok:#16a34a;--warn:#d97706;--bd:#e2e8f0}
html[data-theme="dark"]{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--muted:#94a3b8;--ok:#22c55e;--warn:#f59e0b;--bd:#334155}
.badge.ok{background:#dcfce7;color:var(--ok)}
.badge.warn{background:#fef3c7;color:var(--warn)}
html[data-theme="dark"] .badge.ok{background:#14532d;color:var(--ok)}
html[data-theme="dark"] .badge.warn{background:#78350f;color:var(--warn)}
.verdict{color:var(--muted);font-size:13px;margin:4px 0}
.sug{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px 12px;font:12px/1.5 monospace;color:var(--ok);margin-top:6px;overflow-wrap:anywhere}
.loading{color:var(--muted);padding:12px;text-align:center}
.sec{color:var(--brand);font-weight:600;margin-bottom:8px}
.note{color:var(--muted);font-size:12px;margin-top:8px}
.copybtn{margin-left:8px;font-size:11px;padding:2px 8px}
.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;border-bottom:1px solid var(--bd);padding-bottom:8px}
.tab{padding:6px 14px;border:1px solid var(--bd);background:var(--card);color:var(--muted);border-radius:8px;cursor:pointer;font-size:13px}
.tab:hover{color:var(--fg)}
.tab.active{background:var(--brand);color:#fff;border-color:var(--brand)}
.pane{display:none}
.pane.active{display:block}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,'PingFang SC',sans-serif;padding:16px;max-width:960px;margin:0 auto;transition:background .2s}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
h1{font-size:20px;display:flex;align-items:center;gap:8px}
h1::before{content:'🔍';font-size:18px}
.btn{padding:5px 14px;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px;cursor:pointer;font-size:13px}
.btn:hover{opacity:.85}
.sub{color:var(--muted);font-size:12px;margin-bottom:4px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:12px}
.card h2{font-size:14px;margin-bottom:10px;color:var(--brand)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:12px;white-space:nowrap;width:auto;min-width:120px}
td.val{word-break:break-all;max-width:0;width:100%}
.trunc{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;margin:2px 4px 2px 0}
</style></head><body>
<div class="top">
<h1>fnOS 网络诊断</h1>
<div>
<button class="btn" onclick="copyAll()">复制全部</button>
<button class="btn" id="themeBtn" onclick="toggleTheme()">🌙</button>
</div>
</div>
<div class="sub">v{{VER}} · 打开本页的环境，自动展示请求特征并判断是否移动容器</div>

<div class="tabs">
<button class="tab active" onclick="switchTab('env')">环境</button>
<button class="tab" onclick="switchTab('net')">网络</button>
<button class="tab" onclick="switchTab('diag')">应用诊断</button>
<button class="tab" onclick="switchTab('ctr')">容器</button>
<button class="tab" onclick="switchTab('hist')">历史</button>
</div>

<div class="pane active" id="pane-env">
<div class="card"><h2>当前访问环境</h2><div id="env"></div></div>
<div class="card"><h2>本地持久化存储</h2><div id="store"></div></div>
<div class="card"><h2>请求头 (Request Headers) <button class="btn copybtn" onclick="copyHeaders()">复制</button></h2><table id="hdrs"></table></div>
</div>

<div class="pane" id="pane-net">
<div class="card"><h2>服务/连通性探测 <button class="btn copybtn" onclick="connectivityProbe()">重测</button></h2><div id="conn"></div></div>
<div class="card"><h2>DNS 解析与协议</h2><div id="dns"></div></div>
<div class="card"><h2>登录验证通道 <button class="btn copybtn" onclick="authProbe()">重测</button></h2><div id="auth"></div></div>
</div>

<div class="pane" id="pane-diag">
<div class="card"><h2>应用 / URL 诊断</h2>
<div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap">
<select id="appSel" style="flex:1;min-width:180px;padding:6px;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px;font-size:13px" onchange="appSelChanged()"><option value="">选择 fnOS 应用...</option></select>
<button class="btn" onclick="diagApp()">诊断</button>
</div>
<div style="display:flex;gap:8px;margin-bottom:10px">
<input id="urlInp" placeholder="或输入网址 https://xxx.fnos.net/ 或 http://host:port" style="flex:1;padding:6px;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px;font-size:13px">
<button class="btn" onclick="diagUrl()">分析</button>
</div>
<div id="diag"></div>
</div>
</div>

<div class="pane" id="pane-ctr">
<div class="card"><h2>容器信息 (Docker)</h2><div id="ctr"></div></div>
</div>

<div class="pane" id="pane-hist">
<div class="card"><h2>历史快照</h2><div id="hist"></div></div>
</div>

<div class="note">提示：用飞牛 iOS/Android App 打开本应用，可看到移动容器的真实 Host/UA/转发头，据此配置 dsh 信任域。</div>

<script>
let DATA=null;
function switchTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active', t.getAttribute('onclick').indexOf(name)>=0));
  document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('active', p.id==='pane-'+name));
}
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  const btn=document.getElementById('themeBtn');
  if(btn) btn.textContent = t==='dark' ? '☀️' : '🌙';  // 当前模式, 点击切换
  localStorage.setItem('envprobe-theme', t);
}
function toggleTheme(){
  const cur=document.documentElement.getAttribute('data-theme');
  applyTheme(cur==='dark' ? 'light' : 'dark');
}
function truncate(v, n){
  if(!v) return '';
  const s=String(v);
  if(s.length<=n) return '<span class="trunc" title="'+s.replace(/"/g,'&quot;')+'">'+s+'</span>';
  const esc=s.slice(0,n).replace(/&/g,'&amp;').replace(/</g,'&lt;')+'…';
  return '<span class="trunc" title="'+s.replace(/"/g,'&quot;')+'" onclick="this.textContent=\\''+s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,'\\\\\\'')+'\\'">'+esc+'</span> <button class="btn copybtn" onclick="copyText(\\''+s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,'\\\\\\'')+'\\')">复制</button>';
}
function copyText(t){
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(t).then(()=>flash('已复制')).catch(()=>legacyCopy(t));
  }else{
    legacyCopy(t);
  }
}
function legacyCopy(t){
  const ta=document.createElement('textarea');
  ta.value=t; ta.style.cssText='position:fixed;opacity:0;top:0;left:0;pointer-events:none';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try{ document.execCommand('copy'); flash('已复制'); }
  catch(e){ flash('复制失败，请长按选择文本'); }
  document.body.removeChild(ta);
}
function flash(msg){ const d=document.createElement('div'); d.textContent=msg; d.style.cssText='position:fixed;top:16px;right:16px;background:var(--ok);color:#fff;padding:6px 14px;border-radius:8px;z-index:99'; document.body.appendChild(d); setTimeout(()=>d.remove(),1200); }
function copyAll(){
  if(!DATA) return;
  const lines=[`环境: ${DATA.env.label}`,`来源IP: ${DATA.client_ip}`];
  DATA.verdicts.forEach(v=>lines.push(v));
  lines.push('--- trusted_hosts.conf ---');
  lines.push(DATA.trusted.join('\\n'));
  lines.push('--- headers ---');
  Object.entries(DATA.headers).forEach(([k,v])=>lines.push(`${k}: ${v}`));
  copyText(lines.join('\\n'));
}
function copyHeaders(){
  if(!DATA) return;
  const lines=Object.entries(DATA.headers).map(([k,v])=>`${k}: ${v}`);
  copyText(lines.join('\\n'));
}
function storageProbe(){
  const el=document.getElementById('store');
  if(!el) return;
  const out=[];
  const mark=(name,ok,detail)=>{ out.push(`<span class="badge ${ok?'ok':'warn'}">${name}: ${ok?'可用':'不可用'}</span>${detail?' <span class="verdict" style="display:inline">'+detail+'</span>':''}`); };
  // localStorage
  try{ localStorage.setItem('__ep_t','1'); mark('localStorage', localStorage.getItem('__ep_t')==='1'); localStorage.removeItem('__ep_t'); }
  catch(e){ mark('localStorage', false, String(e)); }
  // sessionStorage
  try{ sessionStorage.setItem('__ep_t','1'); mark('sessionStorage', sessionStorage.getItem('__ep_t')==='1'); sessionStorage.removeItem('__ep_t'); }
  catch(e){ mark('sessionStorage', false, String(e)); }
  // cookie
  try{ document.cookie='__ep_t=1;path=/'; mark('Cookie', document.cookie.indexOf('__ep_t=1')>=0); document.cookie='__ep_t=;path=/;max-age=0'; }
  catch(e){ mark('Cookie', false, String(e)); }
  el.innerHTML = out.join('<br>') || '<div class="verdict">无结果</div>';
}
async function authProbe(){
  const el=document.getElementById('auth');
  if(!el) return;
  el.innerHTML='<div class="loading">测试跳转链路中...</div>';
  try{
    const r=await fetch('/api/redirect-probe', {redirect:'follow'});
    const t=await r.json();
    const ok = r.ok && t && t.ok;
    el.innerHTML =
      `<span class="badge ${ok?'ok':'warn'}">跳转通道: ${ok?'正常':'异常'}</span>`+
      `<div class="verdict">HTTP ${r.status} · 302 重定向已${r.redirected?'跟随':'未跟随'} · ${t.msg||''}</div>`+
      (ok?'':'<div class="verdict" style="color:var(--warn)">若此处异常, 登录后跳转可能失败 (类似 9Router 无法登录跳转)</div>');
  }catch(e){
    el.innerHTML=`<span class="badge warn">跳转通道: 异常</span><div class="verdict">${String(e)}</div><div class="verdict" style="color:var(--warn)">webview 可能拦截了重定向, 登录跳转会失败</div>`;
  }
}
async function connectivityProbe(){
  const el=document.getElementById('conn');
  if(!el) return;
  el.innerHTML='<div class="loading">探测中...</div>';
  try{
    const r=await fetch('/api/connectivity'); const d=await r.json();
    let h=`<div class="verdict">探测时间: ${d.ts} (101 到各目标)</div><table style="word-break:break-all"><tr><th>目标</th><th>地址</th><th>状态</th><th>延迟</th></tr>`;
    d.results.forEach(x=>{
      h+=`<tr><td>${x.name}</td><td>${x.host}:${x.port}</td><td><span class="badge ${x.ok?'ok':'warn'}">${x.ok?'可达':'不可达'}</span></td><td>${x.ok?x.ms+' ms':(x.err||'')}</td></tr>`;
    });
    h+='</table>';
    el.innerHTML=h;
  }catch(e){ el.innerHTML=`<div class="verdict">探测失败: ${e}</div>`; }
}
function dnsProbe(){
  const el=document.getElementById('dns');
  if(!el) return;
  let h='';
  const dns=DATA.dns||{};
  h+=`<div class="verdict">当前域名: <b>${dns.host||'-'}</b></div>`;
  if(dns.ips){
    h+='<div class="verdict">解析 IP ('+dns.count+' 个):</div>';
    h+=dns.ips.map(ip=>`<div class="sug">${ip}</div>`).join('');
  }else if(dns.error){
    h+=`<div class="verdict">解析失败: ${dns.error}</div>`;
  }
  // 协议 / iframe / WebSocket
  const inFrame = window.self !== window.top;
  const proto = location.protocol;
  h+=`<div class="sec" style="margin-top:10px">协议与运行环境</div>`;
  h+=`<div class="verdict">协议: <b>${proto}</b> (${proto==='https:'?'HTTPS 加密':'HTTP 明文'})</div>`;
  h+=`<div class="verdict">iframe 内嵌: <span class="badge ${inFrame?'warn':'ok'}">${inFrame?'是 (被嵌入)':'否 (独立窗口)'}</span></div>`;
  h+=`<div class="verdict">WebSocket: <span id="wsBadge" class="badge warn">检测中...</span></div>`;
  el.innerHTML=h;
  // WebSocket 检测
  try{
    const wsUrl=(proto==='https:'?'wss://':'ws://')+location.host;
    const ws=new WebSocket(wsUrl);
    ws.onopen=()=>{ document.getElementById('wsBadge').textContent='可用'; document.getElementById('wsBadge').className='badge ok'; ws.close(); };
    ws.onerror=()=>{ document.getElementById('wsBadge').textContent='不可用 (可能被拦截)'; document.getElementById('wsBadge').className='badge warn'; };
    setTimeout(()=>{ if(ws.readyState!==1 && ws.readyState!==3){ ws.close(); } }, 3000);
  }catch(e){
    document.getElementById('wsBadge').textContent='不可用: '+e;
  }
}
async function loadHistory(){
  const el=document.getElementById('hist');
  if(!el) return;
  try{
    const r=await fetch('/api/history'); const d=await r.json();
    if(!d.history || d.history.length===0){
      el.innerHTML='<div class="verdict">暂无历史记录（每次打开本页自动记录一条）</div>';
      return;
    }
    let h='<table><tr><th>时间</th><th>Host</th><th>来源IP</th><th>环境</th><th>标记</th></tr>';
    d.history.forEach(x=>{
      const marks=[];
      if(x.mobile) marks.push('<span class="badge warn">移动</span>');
      if(x.fn_domain) marks.push('<span class="badge warn">FN</span>');
      h+=`<tr><td>${x.ts}</td><td>${x.host}</td><td>${x.ip}</td><td>${x.env}</td><td>${marks.join('')||'-'}</td></tr>`;
    });
    h+='</table>';
    el.innerHTML=h;
  }catch(e){ el.innerHTML=`<div class="verdict">加载失败: ${e}</div>`; }
}
async function loadApps(){
  const sel=document.getElementById('appSel');
  if(!sel) return;
  try{
    const r=await fetch('/api/apps'); const d=await r.json();
    if(!d.ok || !d.apps){ sel.innerHTML='<option value="">应用读取失败</option>'; return; }
    sel.innerHTML='<option value="">选择 fnOS 应用...</option>';
    d.apps.forEach(a=>{
      const label = a.display && a.display!==a.name ? `${a.display} (${a.name})` : a.name;
      const opt=document.createElement('option'); opt.value=a.name; opt.textContent=label;
      sel.appendChild(opt);
    });
  }catch(e){ sel.innerHTML='<option value="">应用加载失败</option>'; }
}
function appSelChanged(){
  const sel=document.getElementById('appSel');
  const url=document.getElementById('urlInp');
  if(sel && url && sel.value) url.value=sel.value;  // 选中应用填入 URL 输入框
}
async function renderDiag(d){
  const el=document.getElementById('diag');
  if(!el) return;
  if(!d.ok){ el.innerHTML=`<div class="verdict">${d.error||'失败'}</div>`; return; }
  let h='';
  h+=`<div class="verdict">输入: <b>${d.input}</b></div>`;
  h+=`<div class="verdict">Host: <b>${d.host}</b> · 端口: <b>${d.port}</b>${d.proto?' · 协议: '+d.proto:''}</div>`;
  if(d.dns && d.dns.ips) h+=`<div class="verdict">解析 IP (${d.dns.count}): ${d.dns.ips.join(', ')}</div>`;
  else if(d.dns && d.dns.error) h+=`<div class="verdict">DNS 解析失败: ${d.dns.error}</div>`;
  h+=`<div class="verdict">可达性: ${d.reachable===true?'<span class="badge ok">可达</span>':(d.reachable?'<span class="badge warn">不可达</span>':'未知')}</div>`;
  h+='<div class="sec" style="margin-top:10px">信任域建议 (trusted_hosts.conf) <button class="btn copybtn" onclick="copyText(d.trusted.join(\\'\\n\\'))">复制</button></div>';
  h+='<div class="sug">'+d.trusted.join('\\n')+'</div>';
  el.innerHTML=h;
}
async function diagApp(){
  const sel=document.getElementById('appSel');
  const val=sel ? sel.value : '';
  if(!val){ flash('请先选择应用'); return; }
  await doDiag(val);
}
async function diagUrl(){
  const url=document.getElementById('urlInp');
  const val=url ? url.value.trim() : '';
  if(!val){ flash('请输入网址'); return; }
  await doDiag(val);
}
async function doDiag(q){
  const el=document.getElementById('diag');
  if(el) el.innerHTML='<div class="loading">诊断中...</div>';
  try{
    const r=await fetch('/api/diagnose?q='+encodeURIComponent(q));
    const d=await r.json();
    renderDiag(d);
  }catch(e){ if(el) el.innerHTML=`<div class="verdict">诊断失败: ${e}</div>`; }
}
async function load(){
  try{
    const r=await fetch('/api/probe'); DATA=await r.json();
    // 主题恢复 (默认日)
    const t=localStorage.getItem('envprobe-theme')||'light';
    applyTheme(t);
    // 环境
    let h='';
    h+=`<span class="badge ok">${DATA.env.label}</span>`;
    if(DATA.env.mobile_container) h+=`<span class="badge warn">移动容器</span>`;
    if(DATA.env.fn_domain) h+=`<span class="badge warn">FN Connect</span>`;
    h+=`<div class="verdict">来源 IP: <b>${DATA.client_ip}</b></div>`;
    DATA.verdicts.forEach(v=>{h+=`<div class="verdict">${v}</div>`;});
    if(DATA.env.mobile_url) h+=`<div class="verdict">移动容器地址: <b>${DATA.env.mobile_url}</b></div>`;
    h+='<div class="sec" style="margin-top:10px">trusted_hosts.conf 建议 <button class="btn copybtn" onclick="copyText(DATA.trusted.join(\\'\\n\\'))">复制</button></div>';
    h+='<div class="sug">'+DATA.trusted.join('\\n')+'</div>';
    document.getElementById('env').innerHTML=h;
    // 请求头
    let rows='';
    for(const [k,v] of Object.entries(DATA.headers)){
      rows+=`<tr><th>${k}</th><td class="val">${truncate(v,120)}</td></tr>`;
    }
    document.getElementById('hdrs').innerHTML=rows||'<tr><td colspan="2">无</td></tr>';
    // 容器
    let c='';
    if(DATA.containers.ok){
      if(DATA.containers.count===0){
        c+='<div class="verdict">未发现 Docker 容器（当前为裸机安装，无容器）</div>';
      }else{
        c+=`<div class="verdict">共 <b>${DATA.containers.count}</b> 个容器</div>`;
        c+='<table style="word-break:break-all"><tr><th>名称</th><th>镜像</th><th>状态</th><th>端口</th></tr>';
        DATA.containers.containers.forEach(x=>{
          c+=`<tr><td>${x.name}</td><td>${x.image}</td><td>${x.status}</td><td>${x.ports}</td></tr>`;
        });
        c+='</table>';
      }
    }else if(DATA.containers.available===false){
      c+='<div class="verdict">本机未安装 Docker（应用为原生安装）</div>';
    }else{
      c+=`<div class="verdict">无法读取容器: ${DATA.containers.error||'权限不足'}。可手动查看 \`docker ps -a\`</div>`;
    }
    document.getElementById('ctr').innerHTML=c;
    // 本地持久化存储 + 登录验证通道 + 连通性 + DNS/协议 + 历史
    storageProbe();
    authProbe();
    dnsProbe();
    loadHistory();
    connectivityProbe();
    loadApps();
  }catch(e){
    document.getElementById('env').innerHTML='<div class="verdict">加载失败: '+e+'</div>';
  }
}
load();
</script>
</body></html>
"""

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _probe(self):
        headers = {k.lower(): v for k, v in self.headers.items()}
        host = headers.get("host", "")
        client_ip = self.client_address[0]
        env, verdicts = detect_environment(headers, host, client_ip)
        trusted = suggest_trusted(host)
        containers = get_containers()
        dns = resolve_dns(host)
        # 保存历史快照
        save_history({
            "ts": __import__("time").strftime("%F %T"),
            "host": host, "ip": client_ip, "env": env["label"],
            "mobile": env["mobile_container"], "fn_domain": env["fn_domain"],
        })
        return {
            "headers": headers,
            "client_ip": client_ip,
            "env": env,
            "verdicts": verdicts,
            "trusted": trusted,
            "containers": containers,
            "dns": dns,
            "server": {"lan_ip": LAN_IP, "hostname": socket.gethostname(), "version": APP_VERSION},
        }

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/" or path == "":
            body = PAGE.replace("{{BRAND}}", BRAND).replace("{{VER}}", APP_VERSION).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/probe":
            self._json(self._probe())
        elif path == "/api/redirect-probe":
            # 登录验证通道探测: 302 跳转测试 (模拟登录跳转链路)
            # 前端 fetch follow 后 redirected=true 说明跳转通道正常 (webview 不拦截)
            self.send_response(302)
            self.send_header("Location", "/api/redirect-ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/api/redirect-ok":
            self._json({"ok": True, "redirected": "yes", "msg": "登录跳转通道正常 (302 重定向可跟随)"})
        elif path == "/api/connectivity":
            self._json({"ok": True, "results": probe_connectivity(), "ts": __import__("time").strftime("%F %T")})
        elif path == "/api/history":
            self._json({"ok": True, "history": load_history()})
        elif path == "/api/apps":
            self._json({"ok": True, "apps": list_apps()})
        elif path == "/api/diagnose":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = (q.get("q") or q.get("url") or [""])[0]
            self._json(diagnose_url(target))
        elif path == "/health":
            self._json({"ok": True, "version": APP_VERSION})
        else:
            self.send_error(404)

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    ThreadedServer(("0.0.0.0", PORT), Handler).serve_forever()
