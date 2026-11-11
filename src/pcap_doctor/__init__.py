"""pcap-doctor: 从 pcap 里找出网络慢/断的根因，并给出证据。"""

import logging

# 没装 Npcap/libpcap 时 scapy 会打一条 warning；离线读写 pcap 不受影响。
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

__version__ = "0.1.0"
