# 🛰️ fn-netdiag — fnOS 网络诊断

[![GitHub release](https://img.shields.io/github/v/release/techysy/fn-netdiag-fnos?label=Latest&color=blue)](https://github.com/techysy/fn-netdiag-fnos/releases)
[![License](https://img.shields.io/github/license/techysy/fn-netdiag-fnos?color=green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/techysy/fn-netdiag-fnos?style=social)](https://github.com/techysy/fn-netdiag-fnos)
[![Platform](https://img.shields.io/badge/platform-fnOS-blueviolet)](https://www.fnos.net/)
[![Arch](https://img.shields.io/badge/arch-x86_64%20%7C%20aarch64-lightgrey)]()
[![Zero deps](https://img.shields.io/badge/deps-zero-success)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)]()

**fnOS 网络诊断工具** — 展示当前访问环境的请求特征，识别移动容器/FN Connect 域名，诊断其他应用，辅助配置 dsh 信任域。

> 🏷️ 原名 `env-probe`，更名后定位更通用、不局限移动端。

---

## ✨ 功能

### 🔍 环境识别
- 展示当前访问环境的**完整请求头**（Host / User-Agent / 转发头 / 来源 IP）
- 识别 **移动容器**（飞牛 App 内嵌 webview，UA 特征 + FN Connect 域名动态判断）
- 识别 **FN Connect 域名**（`*.fnos.net`）与局域网直连
- 展示当前访问 URL 与 **Docker 容器信息**

### 🛡️ 信任域建议
- 根据当前 Host 自动给出 **`trusted_hosts.conf` 建议**（如 `dsh.techysy.fnos.net` + `fnos.net`）
- 一键复制，直接配置 dsh 等应用信任域

### 🌐 网络诊断
- **连通性探测**：dsh / 9Router / mihomo / GitHub / DeepSeek / FN Connect TCP 可达性 + 延迟
- **DNS 解析**：当前域名解析 IP 列表
- **协议检测**：HTTPS/HTTP、iframe 内嵌、WebSocket 可用性

### 🔐 登录验证通道
- 302 跳转链路测试，检测 webview 是否拦截重定向（类似 9Router 无法登录跳转的场景）

### 💾 存储探测
- localStorage / sessionStorage / Cookie 读写测试（移动容器 webview 可能禁用）

### 🔍 应用诊断
- 枚举 fnOS 已安装应用列表（dsh / 9Router / 1Panel 等），选中即诊断
- 输入网址分析：Host / 端口 / DNS / 可达性 / 信任域建议

### 🕘 历史快照
- 每次打开自动记录环境信息，方便对比不同访问方式

---

## 📋 标签页布局

| Tab | 内容 |
|-----|------|
| 🏠 环境 | 访问环境 + 本地存储 + 请求头 |
| 🌐 网络 | 连通性 + DNS/协议 + 登录通道 |
| 🔍 应用诊断 | 应用列表 + URL 分析 |
| 🐳 容器 | Docker 容器信息 |
| 🕘 历史 | 环境快照 |

---

## 📦 安装

1. 从 [Releases](https://github.com/techysy/fn-netdiag-fnos/releases) 下载 `fn-netdiag-*.fpk`
2. fnOS 应用中心 → 手动安装 → 选择 fpk
3. 安装后从桌面/飞牛 App 打开「fnOS 网络诊断」

> 若之前装过 `env-probe`，需先卸载再安装（appname 已变更）。

---

## 🖥️ 使用

- **桌面浏览器**：直接打开应用，查看当前访问环境
- **移动容器**：用飞牛 iOS/Android App 打开，查看移动容器真实 Host/UA/转发头
- **配置信任域**：复制「信任域建议」内容写入对应应用的 `trusted_hosts.conf`

---

## 🔧 技术栈

- **依赖**：fnOS 系统自带 Python 3（`/usr/bin/python3`，实测 3.11.2），非依赖应用，manifest 无需声明
- 零第三方依赖 Python 标准库（`http.server`），单文件后端
- 内嵌 HTML/CSS/JS 前端，无构建步骤
- 端口 `28002`，生命周期由 `cmd/main` 管理（启动时定位 python3 绝对路径，适配 App Center 受限 PATH）

---

## 📚 文档

- [CHANGELOG.md](CHANGELOG.md) — 更新日志

---

## 📄 License

[MIT](LICENSE)
