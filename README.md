# LoopFinder · 校园网教研室与弱电间环路快速定位仪

![Version](https://img.shields.io/badge/version-2.1.0-blue)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey)
![Python](https://img.shields.io/badge/python-3.9%2B-green)
![Offline](https://img.shields.io/badge/mode-100%25%20Offline-orange)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

专为学校网络运维打造的 **macOS / Windows 便携桌面定位工具**，解决“大教研室私接家用路由器/傻瓜交换机导致二层广播风暴”以及“弱电间华为/H3C/锐捷/思科/TP-LINK 混杂品牌汇聚与接入交换机逐跳追查”的全链路排障痛点，同时覆盖**三层路由环路**与 **Syslog 实时告警监听**。

> 📖 **详细图文操作与四大现场排障 SOP，请阅读完整文档：[《LoopFinder 完整使用手册》](docs/使用手册.md)**

---

## 核心特性

### 1. 教研室现场定位（无需交换机权限，笔记本直连网口）
* **主动二层环路探针（`EtherType 0x88B5`）**：macOS 内置**零依赖原生 `/dev/bpf*`**（`BIOCSSEESENT=0` 内核级过滤本机回显），Windows 支持 Npcap + Scapy；空载支路毫秒级测环，超过 400 pps 自动停发防加剧风暴。
* **被动风暴与重复帧指纹听诊**：0.5 秒粒度实时波形图，250ms 滑动窗口帧哈希揪出正在打转的重复广播帧，内置三档灵敏度预设（小办公室 / 大教研室 / 机房大 VLAN）。
* **私接小路由器 + ARP 冲突双捕手**：主动 `DHCPDISCOVER` + 被动 ARP 私网暴露，自动读取 80/8080 Web 管理页识别具体型号（如 `TP-LINK TL-WR886N`、`MiWiFi`），同步捕获 ARP IP/网关冲突。
* **上联交换机自动识别（LLDP / CDP / STP）**：插上未贴标签的墙面面板即可自动识别上联交换机、端口、管理 IP 与 VLAN，一键跳转弱电间排查。
* **二分法拔线向导（带撤销）+ 声音雷达**：拔掉故障桌面支线后 1 秒内界面变绿并响起清脆恢复提示音，最快 $\lceil\log_2 N\rceil$ 步锁定单根问题网线。
* **一键导出 Wireshark `.pcap`**：环形缓存最近 3,000 帧原始以太网包，随时导出标准 `.pcap` 取证复盘。

### 2. 弱电间多品牌汇聚/接入交换机排查（纯 Python SNMPv1/v2c）
* **跨品牌零依赖**：通吃华为、新华三 H3C、锐捷、思科、TP-LINK、中兴、Aruba 等混杂环境，支持 SNMPv1 与 `GETNEXT` 自动回退，并读取主流厂商交换机 CPU 利用率。
* **资产簿 + 一键并发扫全楼**：按教学楼管理不同团体名设备，并发双采样 ~3 秒排出整栋楼广播风暴与实时 MAC 漂移风险榜。
* **一键自动逐跳顺藤摸瓜**：从核心/汇聚交换机出发，沿 LLDP 自动跨品牌下钻到最末端教研室墙面信息点。
* **可视化端口矩阵 + 入/出向广播方向对比 + MAC 反查物理口**：同时比对入向与出向广播 PPS，一眼区分「广播源头灌入口」与「受害转发口」。

### 3. Console 串口直连 · Syslog 实时雷达 · 三层路由环路 · SSH/日志解析
* **Console 串口直连自动定位（机房带外神器）**：插上 USB 转 Console 线（macOS 零依赖原生 `termios`，Windows 支持 `pyserial`），自动识别华为/H3C/锐捷/思科/TP-LINK 提示符，隔 3 秒双采样入向广播计数器并算差值，**即便全网瘫痪、SNMP/SSH 断联也能一键标红广播源头口 + LLDP 下联交换机**。
* **Syslog 告警雷达（UDP 1514 / 514）**：被动接收华为 `%LBDT`、H3C `MAC_MOVE`、锐捷 `RLDP`、思科 `MACFLAP_NOTIF` 推送，秒级报警并匹配教研室房间号。
* **三层路由环路检测**：跨平台 `traceroute` / `tracert` 自动高亮重复跳闭环。
* **多品牌 SSH 只读巡检 & Console 串口日志一键粘贴解析**。

### 4. 台账 · 防环加固脚本生成 · 工单报告
* **交换机端口 ↔ 教研室面板 CSV 台账**（自动归一化 `GE0/0/14` / `GigabitEthernet0/0/14` / `Gi0/0/14`）。
* **五品牌防环加固脚本一键生成器**（环路检测 + BPDU 保护 + 风暴抑制 + DHCP Snooping + Syslog 推送）。
* **双格式报告导出**：支持**可打印/另存 PDF 的 HTML 排查报告**与 **Markdown 工单报告**。
* **100% 离线可用 + 暗色/亮色主题一键切换**（适配昏暗弱电间与强光教研室）。

---

## 快速上手

### macOS（零依赖直接运行）
```bash
# 1. 初次体验：启动内置仿真演练模式（模拟 302 大教研室环路 + 3 级弱电间跨品牌追踪）
python3 app.py --demo

# 2. 现场真实排障：提权解锁 /dev/bpf* 实时二层抓包与主动探针
sudo python3 app.py
```
也可直接双击 `启动_macOS.command`。

### Windows 10/11
1. 安装 Python 3.9+（勾选 `Add Python to PATH`）与 [Npcap](https://npcap.com/)（勾选 *WinPcap API-compatible Mode*）。
2. 安装可选依赖：
   ```bat
   pip install -r requirements.txt
   ```
3. 右键 **以管理员身份运行** `启动_Windows.bat`。

### 打包为独立桌面软件（.app / .exe）
* **macOS**：`bash scripts/build_macos.sh` → `dist/LoopFinder.app`
* **Windows**：`scripts\build_windows.bat` → `dist\LoopFinder\LoopFinder.exe`

---

## 项目结构

```text
├── app.py                           # 跨平台桌面启动入口（支持 pywebview / Chrome/Edge --app）
├── 启动_macOS.command               # macOS 一键双击启动器
├── 启动_Windows.bat                 # Windows 一键启动器
├── docs/
│   └── 使用手册.md                  # 完整运维操作手册与四大实战 SOP
├── loopfinder/
│   ├── core/
│   │   ├── capture.py               # 二层抓包、重复帧指纹、主动探针、ARP冲突与PCAP环形缓存
│   │   ├── mac_bpf.py               # macOS 零依赖原生 /dev/bpf* 收发引擎
│   │   ├── packet_parser.py         # 纯 Python 以太网/VLAN/ARP/DHCP/STP/LLDP/CDP/0x88B5 解析
│   │   ├── pcap_writer.py           # 标准 Wireshark .pcap 导出器
│   │   ├── rogue_router.py          # 私接小路由器 Web 型号指纹探测
│   │   ├── snmp.py                  # 纯 Python SNMPv1/v2c、双采样、并发扫楼与自动逐跳追踪
│   │   ├── inventory.py             # 弱电间多品牌交换机资产簿
│   │   ├── syslog_listener.py       # 实时被动 UDP Syslog 环路告警雷达
│   │   ├── console_inspector.py     # 跨平台 Console 串口直连双采样定位广播源头口
│   │   ├── l3_tracer.py             # 跨平台三层路由环路检测器
│   │   ├── ssh_inspector.py         # 多品牌 SSH 只读诊断、离线日志解析与防环配置生成器
│   │   ├── ledger.py                # 交换机端口 ↔ 教研室面板台账
│   │   ├── interfaces.py            # 跨平台网卡发现与权限检测
│   │   └── simulator.py             # 校园网教研室与 3 级弱电间仿真演练引擎
│   ├── data/
│   │   ├── oui_vendors.py           # 离线 OUI 厂商库（覆盖国产常见家用路由器与企业交换机）
│   │   └── sample_ledger.csv        # 示例教研室面板台账模板
│   └── web/
│       ├── server.py                # 本地多线程 HTTP + SSE 实时推送服务
│       └── static/                  # 100% 离线桌面控制台前端 (HTML/CSS/JS)
├── scripts/
│   ├── build_macos.sh               # macOS PyInstaller .app 打包脚本
│   └── build_windows.bat            # Windows PyInstaller .exe 打包脚本
└── tests/
    └── test_core.py                 # 单元测试与集成测试套件
```

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

## License

[MIT](LICENSE)
