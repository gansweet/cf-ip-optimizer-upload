# Amos · CF 优选

Cloudflare IP / 域名优选工具：**C 语言内核 + 网页前端，前后端一体**。程序启动后会自己打开页面，不需要分别启动前端和后端。

内核（`cf_ip_test_tls.c`）负责随机生成 IP、真实 TLS 握手测速、下载测速、筛选，并把结果上传到 GitHub / SFTP，再通过 Telegram / 邮件通知你。前端（`web/index.html`）是一个单文件页面，桌面版、Docker、安卓 App 共用同一份。

默认端口：**18443**（浏览器访问 `http://127.0.0.1:18443/`）。

## 功能

- **优选区**：IPv4、IPv6、🌐 域名优选可单选或多选。官方网段地址（`https://www.cloudflare.com/ips-v4`、`ips-v6`）可编辑、保存、恢复、拉取，拉取到的内容显示在下方编辑框里，也可手动改；域名优选的列表地址由你自填，也可直接手写域名（每行一个，`#` 后为备注）。
- **端口**：443（默认）、2053、2083、2087、2096、8443。非 443 时，测试用该端口，输出写成 `6.6.6.6:2053#JP`、`cf.example.com:8443#域名`、`[2606:4700::1]:2053#JP`；443 不写端口。
- **筛选参数**：优选个数、延迟范围、最大丢包、**下载速度**（最低 MB/s、测速秒数、测速文件）。
- **节点区**：多个 SNI 轮换做真实 TLS 测试（证书与域名校验始终开启）；网段很多时，**先随机抽取若干网段，再由 C 程序在每个网段内随机生成 IP** 来测试；每个测试次数、超时、并发可调。域名模式用 `CONNECT_TO` 直连该域名，SNI 取你填写的节点域名（留空则用域名本身）。
- **上传区**：GitHub（优先走 REST API；API 读写失败时自动改用 git）和 SFTP，可同时写多个文件。每个文件有独立后缀，`#` 后可以是英文、中文、emoji 等，如 `#SG`、`#优选域名`、`#JP_域名`、`#🇸🇬`；可设每个文件写入的个数，少于总数时按文件轮询分配。**每次上传前先读取原文件，复测其中的 IP 和域名，剔除失效项，与新结果合并后覆盖原文件**，文件名和路径不变，下载链接保持稳定。
- **手动上传与查看**：结果区有「GitHub 上传 / SFTP 上传 / GitHub 查看 / SFTP 查看」四个按钮。自动上传失败时，点「上传」即可接着完成：失败时会保留“待上传内容”（已经复测过远端旧条目），手动上传直接合并上传、不再复测；没有待上传内容时，则重新执行一次完整上传（先复测远端旧条目、剔除失效项，再与最近一次筛选结果合并）。「查看」可以打开当前要上传的内容（待上传内容 / 草稿 / 远端现有文件），点「编辑」增删条目，「保存」后再点「上传」。你手动新增的条目原样保留（自带的 `#后缀` 优先），远端原有条目会先复测；你删掉的条目不会被加回来。上传按钮上的 ● 表示还有待上传内容。
- **自动运行**：每隔 12 / 24 / 48 / 72 小时或 7 天，或每周某天某时；完成后自动通知。
- **开机自启**：页面里点「设为开机自启」，或运行 `./cfip --autostart`（Linux systemd 用户服务、macOS LaunchAgent、Termux:Boot）。
- **通知**：Telegram（Token + Chat ID），邮件（SMTP：服务器、端口、账号、授权码、收件邮箱，如 `smtp.163.com` / 465）。每次筛选 + 上传结束后推送状态、前 10 个优选结果和下载链接。
- **代理 / VPN 提示**：点「开始」前会检测代理环境变量、fake-ip DNS、`tun` / `wg` 等虚拟网卡。检测到时会弹窗提醒，你可以取消去关闭代理，也可以确认继续——结果、通知里会标注"结果可能有误"。无结果时，状态栏会给出失败原因统计（超时 / 证书 / 连接 / 其他）。测速本身一律直连，不走环境变量里的代理。
- **皮肤**：星空黑、玫瑰红、山野绿、海洋蓝、翡冷翠，点左上角 logo 切换。
- **结果区**：实时进度、结果表、下载链接、导出 CSV / TXT。

## 项目结构

```
cf_ip_test_tls.c        C 内核 + 内置 HTTP 服务（单文件）
web/index.html          前端页面（HTML + CSS + JS，单文件）
assets/                 logo.svg、各平台图标（PNG / ICO / ICNS）、make_icons.py、桌面入口
android/                安卓原生壳工程（WebView + JNI 内核 + 前台服务）
install.sh              Linux / Termux / macOS 一键安装
Dockerfile              容器构建
.github/workflows/      build.yml（Linux / macOS / Windows）、android.yml（APK）
data/                   运行后生成：config.txt、secrets.txt（权限 600）、last_run.txt
```

## 使用

**桌面（推荐）**：到 Releases 下载对应平台的包，解压后运行：Windows 双击 `Start-CFIP.bat`（exe 已带 logo），macOS 打开 `CFIP.app`，Linux 运行 `./cfip`。程序会自动打开浏览器。

**Debian / Ubuntu 一键安装**（把仓库推到你的 GitHub 后）：

```bash
curl -fsSL https://raw.githubusercontent.com/gansweet/cf-ip-optimizer-upload/main/install.sh | CFIP_REPO=https://github.com/gansweet/cf-ip-optimizer-upload.git bash
```

脚本会安装依赖、编译、创建桌面图标、加入开机自启并打开页面。

**手动编译**：
- dowload the file
```
git clone https://github.com/gansweet/cf-ip-optimizer-upload.git
cd cf-ip-optimizer-upload
```
- then build and run
```bash
sudo apt update && sudo apt install -y build-essential pkg-config libcurl4-openssl-dev
cc -O2 -Wall -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl) -lpthread
./cfip                       # 自动打开浏览器；加 --no-browser 则不打开
./cfip --autostart           # 加入开机自启（可选）
```

**Docker**：
- dowload the file
```
git clone https://github.com/gansweet/cf-ip-optimizer-upload.git
cd cf-ip-optimizer-upload
```
- then build and run
```bash
docker build -t cfip .
docker run -d --name cfip -p 127.0.0.1:18443:18443 -v $PWD/data:/app/data cfip
```

**Termux（安卓命令行）**：
- dowload the file
```
git clone https://github.com/gansweet/cf-ip-optimizer-upload.git
cd cf-ip-optimizer-upload
		```
- then build and run
```bash
pkg update && pkg install -y clang pkg-config libcurl git
clang -O2 -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl)
./cfip                       # 用 termux-open-url 打开页面，也可手动访问 http://127.0.0.1:18443
```
**iSH isntallation on ipad or iphone
- dowload the file
```
git clone https://github.com/gansweet/cf-ip-optimizer-upload.git
cd cf-ip-optimizer-upload
```
- then build and run
```
apk update
apk add build-base pkgconf curl-dev

cc -O2 -Wall -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl) -lpthread

./cfip
```


**安卓 App**：`android/` 是独立的 Gradle 工程。C 内核编译成 `libcfip.so`，由前台服务在后台运行，WebView 显示同一份前端；定时任务靠前台服务保活。

- 用 GitHub Actions：推送 `v*` 标签或手动运行 `android` 工作流，产物是 `cfip-android.apk`（调试签名，可直接侧载安装）。
- 本地构建：用 Android Studio 打开 `android/` 目录，或 `gradle -p android assembleDebug`。
- 首次启动请允许通知，并在系统设置里允许本应用「自启动」和「后台运行」（不同厂商入口不同）。
- 安卓版暂不支持 SFTP，请用 GitHub 上传。

## 通知与上传说明

- **GitHub**：到 Settings → Developer settings → Fine-grained tokens，只授权目标仓库的 Contents 读写。链接形如 `https://raw.githubusercontent.com/用户名/仓库名/refs/heads/main/ipchosen.txt`。
- **SFTP**：路径填服务器上的真实绝对路径（如 `/var/www/html/data`），再填对应的 https **下载路径**（如 `https://domain.com/wp-content/uploads/2026/01`，下载链接 = 下载路径 + `/` + 文件名；它和 `#后缀` 是两回事），WordPress 可用 `.../wp-content/uploads/2026/01/`。
- **Telegram**：用 @BotFather 创建机器人拿 Token，给机器人发一条消息后，用 @userinfobot 或 `getUpdates` 查 Chat ID。
- **邮件**：以 163 为例，服务器 `smtp.163.com`、端口 `465`，账号填完整邮箱，密码处填 16 位**授权码**（在邮箱设置里开启 SMTP 后获得）。端口 465 走 SSL，其他端口走 STARTTLS。

## GitHub 与 SFTP 上传失败时怎么排查

- **GitHub**：API 请求设有 10 秒连接超时，失败自动重试 3 次（第 2 次只用 IPv4，第 3 次改用 HTTP/1.1）；读取失败时**绝不会**把远端当成“文件不存在”去覆盖。仍然失败时，状态栏会显示真实原因（如 `Timeout was reached`、`HTTP 403 ...`），而不是笼统的“请检查网络”。上传区可以另填一个「git 用 PAT」：API 不通时程序会自动用 git 克隆、提交、推送（需要本机装有 git；留空则复用 API 的 PAT）。git 的 token 只写入 `data/gitcred`（权限 600），不会出现在命令行里。
- **SFTP**：服务器文件路径可以是绝对路径（`/home/用户/domains/域名/public_html/wp-content/uploads/2026/01`），也可以是相对登录目录的路径；两端空格会自动去掉，路径里的空格等特殊字符会自动编码。不合法时，提示会指出是哪个字段、哪个位置的字符有问题。读取旧文件时，只有确认“文件不存在”才当作新文件，超时、登录失败等一律报错并保留待上传内容，不会覆盖服务器上的文件。
- 失败后的内容保存在 `data/stage/`，草稿在 `data/manual/`；点结果区的「上传」按钮重试即可。

## 安全与限制

- 服务默认只监听 `127.0.0.1`，没有登录验证。如需对外开放（`CFIP_BIND=0.0.0.0`），请放在带认证的反向代理后面；Docker 镜像内部监听 `0.0.0.0`，请只映射到本机。
- PAT（含 git 用 PAT）、SFTP 密码、Telegram Token、邮件授权码保存在 `data/secrets.txt`（权限 600），页面不会回显。
- SFTP 首次连接不校验服务器主机密钥，请只连接自己的服务器。
- SNI 请使用自己拥有或获授权测试的域名。
- 结果只代表当前网络和时间。下载测速只测延迟最低的一批（最多 60 个），开启后耗时更长。
- Windows 版基于 MSYS2 构建，尚无 Windows 开机自启；macOS / Windows / 安卓的工作流需要在 GitHub 上实际运行才能确认产物。
