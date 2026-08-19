# Changelog

## [1.0.2] - 2026-08-19

- **修复**: 安装/重启后服务不自启动 —— App Center 启动环境 PATH 不含 python3，cmd/main 用裸 `python3` 找不到。改为定位绝对路径 `/usr/bin/python3`（受限 PATH 也能启动）

## [1.0.1] - 2026-08-19

- **优化**: 容器 Tab 优雅降级（无容器显示提示 / 权限不足友好提示，不再报裸权限错误）
- **修复**: cmd/main stop() 用 `pkill -f server.py` 会误杀其他应用进程（如 mihomo status_server），改为仅匹配本应用路径
- **新增**: get_containers 多路径尝试（docker / sudo docker）

## [1.0.0] - 2026-08-19

- **改名**: `env-probe` → `fn-netdiag`（fnOS 网络诊断），版本从 1.0.0 重新开始
- **新增**: 应用诊断 Tab —— 枚举 fnOS 已安装应用列表 + 输入网址分析（Host/端口/DNS/可达性/信任域建议）
- **修复**: `Can't find variable: dnsProbe` 页面加载失败（JS 括号嵌套错误）
- 页面标题/H1 改为「fnOS 网络诊断」

## [0.1.6] - 2026-08-19

- **修复**: 复制按钮无反应（移动容器/HTTP 非安全上下文 `navigator.clipboard` 不可用 → 降级 `execCommand('copy')`）

## [0.1.5] - 2026-08-19

- **修复**: 页面响应加 `Cache-Control: no-cache`，避免浏览器/webview 缓存旧 JS 导致 `Can't find variable: dnsProbe` 等加载报错

## [0.1.4] - 2026-08-19

- **优化**: 标签页聚合为 4 个（环境[含存储+请求头] / 网络[含连通性+DNS·协议+登录通道] / 容器 / 历史），减少切换成本

## [0.1.3] - 2026-08-19

- **新增**: 服务/连通性探测（dsh/9Router/mihomo/GitHub/DeepSeek/FN Connect TCP 可达性 + 延迟）
- **新增**: DNS 解析详情（当前域名解析 IP 列表）
- **新增**: 协议与运行环境（HTTPS/HTTP、iframe 内嵌检测、WebSocket 可用性）
- **新增**: 历史快照（每次打开自动记录环境信息，可对比不同访问方式）
- **优化**: 标签页新增「连通性 / DNS·协议 / 历史」

## [0.1.2] - 2026-08-19

- **新增**: 本地持久化存储探测（localStorage / sessionStorage / Cookie 读写测试）
- **新增**: 登录验证通道探测（302 跳转链路测试，检测 webview 是否拦截重定向 —— 类似 9Router 无法登录跳转的场景）
- **优化**: 页面改为标签页（Tabs）布局，避免过长滚动

## [0.1.1] - 2026-08-19

- **修复**: 放大镜图标丢失（CSS `content` 的 Unicode 转义被 Python 误解析为八进制）
- **修复**: 请求头表格 key 列单字符竖排（`white-space:nowrap`，仅值列 `break-all`）
- **优化**: 默认日（亮色）模式，切换按钮 emoji 动态显示（🌙/☀️）
- **新增**: 一键复制（复制全部 / 复制请求头 / 复制信任域建议），长值截断 + 点击展开
- **修复**: 安装后服务未启动（数据目录属主错误，install_callback 增加 `chown` 给包用户）

## [0.1.0] - 2026-08-19

- **首发**: 环境探测器 fnOS 应用（零依赖单文件 Python + 内嵌前端，:28002）
- 展示当前访问环境的完整请求头（Host/UA/转发头）+ 来源 IP
- 识别**移动容器**（飞牛 iOS/Android App 内嵌，Host=`office.app.5ddd.com:port`），显示完整访问地址
- 识别桌面浏览器 / FN Connect 域名 / 局域网直连
- 读取 Docker 容器信息（名称/镜像/状态/端口）
- 根据当前 Host 给出 `trusted_hosts.conf` 信任域建议
- 打包双版本 fpk（url + iframe）
