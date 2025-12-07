import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# 数据存储路径
PCAP_SAVE_PATH = BASE_DIR / "data" / "catched_data"
ANALYSIS_RESULT_PATH = BASE_DIR / "data" / "analysis_results"
QQWRY_PATH = BASE_DIR / "data" / "qqwry.dat"

# 分析工具路径
WS_ANALYZER_PATH = Path(r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit-main\target\debug\ws-traffic-analyze-kit.exe")

# 抓包配置
CAPTURE_DURATION = 60  # 默认抓包时长(秒)
DEFAULT_INTERFACE = "Ethernet"  # 默认网络接口
MAX_ANALYSIS_THREADS = 5  # 最大分析线程数

# 确保目录存在
PCAP_SAVE_PATH.mkdir(parents=True, exist_ok=True)
ANALYSIS_RESULT_PATH.mkdir(parents=True, exist_ok=True)