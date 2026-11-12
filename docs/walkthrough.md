# pcap-doctor · 一步一步使用与讲解

按「拿到一段 pcap」的真实顺序写：先跑演示，再看指标，最后能解释每条结论。

## 0. 五分钟路线

1. 跑 `demo`，生成 5 个演示 pcap。
2. 打开 `mixed.html`，看 5 条归因和证据。
3. 用自己的 pcap 跑 `analyze`。
4. 看「指标口径」和「面试怎么讲」。

---

## 1. 它解决什么问题

输入：一个 `.pcap` / `.pcapng` 文件（Wireshark、tcpdump、Npcap 都能导出）。

输出：一份 HTML 报告，回答：

- 哪些 TCP 会话重传高？
- 握手 RTT 是否异常？
- 有没有连接被拒绝、被 RST、零窗口？
- DNS 解析失败还是解析慢？
- 每条结论对应哪些包号和时间点？

它不是 Wireshark 的替代品，而是把「按时间找红色行」变成固定规则和可回归的数字。

---

## 2. 环境准备（Windows）

```powershell
cd C:\ClaudeProjects\pcap-doctor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

只需要 `scapy`。读 pcap 不需要 Npcap；只有实时抓包才需要。

---

## 3. 跑第一次 demo

```powershell
.\.venv\Scripts\python.exe -m src.pcap_doctor demo
```

它会生成 5 个 pcap 到 `demo/`，逐个分析，并把报告写到 `reports/`：

| 场景 | 注入的故障 | 期望发现 |
|---|---|---|
| `normal` | 无 | 0 条 |
| `retransmission` | 同一序号重复发送 | TCP 重传偏高（高） |
| `connection-refused` | SYN 后服务端直接 RST | 连接被拒绝（高） |
| `dns-failure` | NXDOMAIN + 1.2 秒慢解析 | DNS 失败 + DNS 偏慢（中） |
| `mixed` | 上面几种混在一起 + 零窗口 | 5 条 |

打开 `reports/mixed.html`，从上往下看：

1. **结论**：5 条发现，按严重程度排序。
2. **证据**：点开「证据」，能看到 `包 #23（+0.140s）` 这样的定位。
3. **流量最大的会话**：条形图，按载荷字节数。
4. **TCP 会话表**：两端地址、包数、字节、重传、握手 RTT、时长。
5. **DNS 解析表**：域名、客户端、时延、rcode。

---

## 4. 分析自己的 pcap

```powershell
.\.venv\Scripts\python.exe -m src.pcap_doctor analyze capture.pcap `
  --report reports\capture.html `
  --json reports\capture.json
```

有高危发现时让退出码为 1：

```powershell
.\.venv\Scripts\python.exe -m src.pcap_doctor analyze capture.pcap --fail-on-high
```

适合放进巡检脚本：有「连接拒绝 / 重传风暴」就报警。

### 实时抓包（可选）

```powershell
.\.venv\Scripts\python.exe -m src.pcap_doctor capture `
  --seconds 20 --iface "Wi-Fi" --out capture.pcap
```

需要 Npcap（Wireshark 安装包里勾选）并以管理员运行。没装驱动时程序会给出提示，不会抛堆栈；离线路径不受影响。

---

## 5. 指标口径（这是最容易被追问的部分）

| 指标 | 定义 | 为什么要这样定 |
|---|---|---|
| 重传 | 同一方向、同一 `seq`、同一载荷长度第二次出现 | 合法重发、Keep-Alive、乱序不会被误算 |
| 乱序 | 新报文 `seq` 小于该方向已见最大 `seq` | 和重传分开统计，避免互相污染 |
| 握手 RTT | 客户端 SYN → 服务端 SYN-ACK | 只反映网络往返和服务端 accept，不含应用处理 |
| 重复 ACK | 连续、纯 ACK、ack 号相同 | 通常是丢包/乱序触发的快速重传信号 |
| 零窗口 | TCP window = 0 | 接收方缓冲区满，发送方被迫停等 |
| DNS 失败 | response 的 rcode ≠ 0 | 应用「打不开」但 TCP 根本没建立时优先看这里 |
| DNS 时延 | query → response 的时间差 | 首屏慢、接口还没发出时优先看这里 |

阈值在 `src/pcap_doctor/detect.py` 顶部：

| 规则 | 条件 |
|---|---|
| `tcp_retransmission` | ≥ 3 次且 ≥ 1% 包数 |
| `tcp_duplicate_ack` | ≥ 5 个 |
| `tcp_slow_handshake` | ≥ 300 ms |
| `dns_slow` | ≥ 800 ms |
| `top_talker` | ≥ 85% 且总量 ≥ 20 KB |

---

## 6. 代码地图

| 文件 | 职责 |
|---|---|
| `src/pcap_doctor/load.py` | scapy 解析 → `PacketView`，与 scapy 解耦 |
| `src/pcap_doctor/flows.py` | TCP 五元组归并、每条流的指标 |
| `src/pcap_doctor/dns.py` | query/response 配对、时延、rcode |
| `src/pcap_doctor/detect.py` | 规则与证据生成 |
| `src/pcap_doctor/analyze.py` | 把上面几步拼成一次分析 |
| `src/pcap_doctor/report.py` | 单文件 HTML |
| `src/pcap_doctor/demo.py` | 合成 5 个故障 pcap |
| `src/pcap_doctor/cli.py` | demo / analyze / capture |

一次分析：

```text
rdpcap
→ PacketView（IP/TCP/UDP/DNS 字段）
→ 按五元组聚合 TCP 流
→ 每条流算重传/乱序/重复 ACK/零窗口/RTT
→ DNS query/response 配对
→ 规则生成 Finding（严重度 + 证据）
→ HTML 报告
```

---

## 7. 面试怎么讲（三个问题）

**Q1：Wireshark 已经能看重传，为什么还要写这个？**

Wireshark 是交互式排查，结论留在人脑子里；这个项目把指标和阈值固化成代码，能批量跑、能进 CI、能回归。报告还带包号证据，方便回到 Wireshark 复核。

**Q2：怎么避免把合法重发算成丢包？**

重传身份是「方向 + seq + 载荷长度」，第二次出现才计数；纯 ACK、Keep-Alive 不计。乱序单独统计，不和重传混在一起。

**Q3：怎么证明规则没有误报？**

仓库自带 5 个注入了已知故障的合成 pcap，评测按场景比较「期望发现」和「实际发现」。当前 5/5 完全命中，precision/recall 100%。这是小样本回归集，不是通用准确率。

---

## 8. 评测与测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe eval\run_eval.py
```

实测：

| 项目 | 结果 |
|---|---|
| 测试 | 8 passed |
| 场景完全命中 | 5/5 |
| precision / recall | 100% / 100% |

---

## 9. 常见问题

| 现象 | 处理 |
|---|---|
| 提示 `No libpcap provider available` | 读离线 pcap 不受影响；实时抓包才需要 Npcap |
| `capture` 报权限/接口错误 | 安装 Npcap，并用管理员运行；或用 Wireshark 先导出 pcap 再 `analyze` |
| DNS 查询显示「无响应」 | 抓包开始时查询已经发出，或响应落在抓包窗口外；延长抓包时间 |
| 报告里没有某条流 | 只统计 TCP；UDP 除了 DNS 不做流分析 |
| 时间显示与本机差 8 小时 | 报告里显示的是本机时区；pcap 时间戳本身不变 |

## 10. 局限

- 不解密 TLS，看不到应用层内容。
- 不做 HTTP/2、QUIC、WebSocket 协议还原。
- 真实网络的 NAT、分片、中间设备会影响指标，需要结合现场判断。
- 实时抓包依赖 Npcap 和管理员权限；本机 demo/评测走离线路径。
