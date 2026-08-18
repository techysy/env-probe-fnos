#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env-probe — 环境探测器 (零依赖 stdlib http.server)

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
APP_VERSION = os.environ.get("ENV_PROBE_VERSION", "0.1.0")

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
# 移动容器特征: 飞牛 iOS/Android App 内嵌 webview 打开应用时
#   Host = office.app.5ddd.com:<动态端口>  (如 http://office.app.5ddd.com:52575/v1)
MOBILE_CONTAINER_HOST = "office.app.5ddd.com"

def detect_environment(headers, host, client_ip):
    """根据请求头判断访问环境"""
    ua = headers.get("user-agent", "")
    ua_l = ua.lower()
    host_l = (host or "").lower()
    verdicts = []
    env = {"kind": "unknown", "label": "未知环境", "mobile_container": False, "fn_domain": False,
           "mobile_url": ""}

    # 0. 移动容器: Host = office.app.5ddd.com[:port] (飞牛移动 App 内嵌 webview)
    if host_l.startswith(MOBILE_CONTAINER_HOST):
        env["mobile_container"] = True
        env["kind"] = "mobile-container"
        env["label"] = "移动容器 (飞牛 iOS/Android App)"
        # 完整访问地址
        proto = "https" if headers.get("x-forwarded-proto", "") == "https" else "http"
        env["mobile_url"] = f"{proto}://{host}/"
        verdicts.append(f"移动容器域名: {host}")
        verdicts.append(f"完整访问地址: {env['mobile_url']}")
        verdicts.append("→ 配置 dsh 信任域需加: office.app.5ddd.com")

    # 1. 是否移动容器 / 飞牛移动 App (UA 特征)
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
    if mobile_found and not env["mobile_container"]:
        env["mobile_container"] = True
        env["kind"] = "mobile"
        env["label"] = "移动端"
        verdicts.append(f"移动端 UA: {'+'.join(set(mobile_found))}")
    elif not env["mobile_container"]:
        # 2. 桌面浏览器
        if any(b in ua_l for b in ("chrome", "safari", "firefox", "edge", "webkit", "gecko")):
            env["kind"] = "desktop"
            env["label"] = "桌面浏览器"
            verdicts.append("桌面浏览器")

    # 3. 是否 FN Connect 域名
    if host_l.endswith(".fnos.net") or host_l == "fnos.net":
        env["fn_domain"] = True
        env["label"] = f"{env['label']} · FN Connect 域名"
        verdicts.append(f"FN Connect 域名: {host}")

    # 4. 转发头 (统一网关/FN Connect 反向代理通常带)
    fwd_for = headers.get("x-forwarded-for", "")
    xr_ip = headers.get("x-real-ip", "")
    fwd_host = headers.get("x-forwarded-host", "")
    if fwd_for or xr_ip or fwd_host:
        verdicts.append(f"存在反向代理转发头 (X-Forwarded-For: {fwd_for or '-'} / X-Real-IP: {xr_ip or '-'} / X-Forwarded-Host: {fwd_host or '-'})")

    # 5. 是否局域网 IP
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
    # 移动容器: office.app.5ddd.com (飞牛移动 App 内嵌)
    if hostname == MOBILE_CONTAINER_HOST:
        return [MOBILE_CONTAINER_HOST, "*.fnos.net", "fnos.net"]
    if hostname.endswith(".fnos.net") or hostname == "fnos.net":
        return [hostname, "fnos.net"]
    if hostname.startswith("dsh."):
        return [hostname, "fnos.net"]
    return [hostname]

# ── 容器信息 (docker) ─────────────────────────────────────
def get_containers():
    """读取 Docker 容器列表 (名称/镜像/状态/端口/IP)"""
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format",
             "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"],
            capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return {"ok": False, "error": out.stderr.strip() or "docker ps failed"}
        rows = []
        for line in out.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                rows.append({"name": parts[0], "image": parts[1], "status": parts[2], "ports": parts[3]})
        return {"ok": True, "containers": rows, "count": len(rows)}
    except FileNotFoundError:
        return {"ok": False, "error": "docker 不可用"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── HTTP 服务 ─────────────────────────────────────────────
PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>App 环境探测器</title>
<style>
:root{--brand:%(BRAND)s;--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--muted:#94a3b8;--ok:#22c55e;--warn:#f59e0b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,'PingFang SC',sans-serif;padding:16px;max-width:960px;margin:0 auto}
h1{font-size:20px;margin:8px 0 4px;display:flex;align-items:center;gap:8px}
h1::before{content:'\\1F50D';font-size:18px}
.sub{color:var(--muted);font-size:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid #334155;border-radius:10px;padding:14px;margin-bottom:12px}
.card h2{font-size:14px;margin-bottom:10px;color:var(--brand)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #334155;word-break:break-all}
th{color:var(--muted);font-weight:500;width:180px;font-size:12px}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;margin:2px 4px 2px 0}
.badge.ok{background:#14532d;color:var(--ok)}
.badge.warn{background:#78350f;color:var(--warn)}
.verdict{color:var(--muted);font-size:13px;margin:4px 0}
.sug{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 12px;font:12px/1.5 monospace;color:var(--ok);margin-top:6px}
.loading{color:var(--muted);padding:12px;text-align:center}
.sec{color:var(--brand);font-weight:600;margin-bottom:8px}
.note{color:var(--muted);font-size:12px;margin-top:8px}
</style></head><body>
<h1>App 环境探测器</h1>
<div class="sub">v%(VER)s · 打开本页的环境，自动展示请求特征并判断是否移动容器</div>

<div class="card">
<h2>当前访问环境</h2>
<div id="env"></div>
</div>

<div class="card">
<h2>请求头 (Request Headers)</h2>
<table id="hdrs"></table>
</div>

<div class="card">
<h2>容器信息 (Docker)</h2>
<div id="ctr"></div>
</div>

<div class="note">提示：用飞牛 iOS/Android App 打开本应用，可看到移动容器的真实 Host/UA/转发头，据此配置 dsh 信任域。</div>

<script>
async function load(){
  try{
    const r=await fetch('/api/probe'); const d=await r.json();
    // 环境
    let h='';
    h+=`<span class="badge ok">${d.env.label}</span>`;
    if(d.env.mobile_container) h+=`<span class="badge warn">移动容器</span>`;
    if(d.env.fn_domain) h+=`<span class="badge warn">FN Connect</span>`;
    h+=`<div class="verdict">来源 IP: <b>${d.client_ip}</b></div>`;
    d.verdicts.forEach(v=>{h+=`<div class="verdict">${v}</div>`;});
    h+='<div class="sec" style="margin-top:10px">trusted_hosts.conf 建议</div>';
    h+='<div class="sug">'+d.trusted.join('\\n')+'</div>';
    document.getElementById('env').innerHTML=h;
    // 请求头
    let rows='';
    for(const [k,v] of Object.entries(d.headers)){
      rows+=`<tr><th>${k}</th><td>${v}</td></tr>`;
    }
    document.getElementById('hdrs').innerHTML=rows||'<tr><td colspan="2">无</td></tr>';
    // 容器
    let c='';
    if(d.containers.ok){
      c+=`<div class="verdict">共 <b>${d.containers.count}</b> 个容器</div>`;
      c+='<table><tr><th>名称</th><th>镜像</th><th>状态</th><th>端口</th></tr>';
      d.containers.containers.forEach(x=>{
        c+=`<tr><td>${x.name}</td><td>${x.image}</td><td>${x.status}</td><td>${x.ports}</td></tr>`;
      });
      c+='</table>';
    }else{
      c+=`<div class="verdict">${d.containers.error||'获取失败'}</div>`;
    }
    document.getElementById('ctr').innerHTML=c;
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
        return {
            "headers": headers,
            "client_ip": client_ip,
            "env": env,
            "verdicts": verdicts,
            "trusted": trusted,
            "containers": containers,
            "server": {"lan_ip": LAN_IP, "hostname": socket.gethostname(), "version": APP_VERSION},
        }

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/" or path == "":
            body = (PAGE % {"BRAND": BRAND, "VER": APP_VERSION}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/probe":
            self._json(self._probe())
        elif path == "/health":
            self._json({"ok": True, "version": APP_VERSION})
        else:
            self.send_error(404)

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    ThreadedServer(("0.0.0.0", PORT), Handler).serve_forever()
