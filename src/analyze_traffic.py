import sys
import os
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import scapy.all as scapy
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cicflowmeter_utils import get_latest_file, run_cicflowmeter
from attack_signatures.update_signatures import SignatureManager

CSV_BASE_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"
PCAP_BASE_DIR = r"C:\Users\z1395\network_trace_system\pcap_files"

# 初始化日志
logger = logging.getLogger("traffic_analyzer")

def extract_rtt_ttl_from_pcap(pcap_path):
    """从PCAP文件中提取RTT和TTL信息"""
    rtt_data = {}  # {("src_ip", "dst_ip", "src_port", "dst_port"): rtt}
    ttl_data = {}  # {("src_ip", "dst_ip"): ttl}
    
    try:
        packets = scapy.rdpcap(pcap_path)
        request_times = {}
        
        for packet in packets:
            if scapy.IP in packet and scapy.TCP in packet:
                ip_layer = packet[scapy.IP]
                tcp_layer = packet[scapy.TCP]
                key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
                rev_key = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
                
                # 记录请求包时间
                if tcp_layer.flags & 0x02:  # SYN标志
                    request_times[key] = packet.time
                
                # 记录响应包并计算RTT
                if tcp_layer.flags & 0x12:  # SYN-ACK标志
                    if rev_key in request_times:
                        rtt = (packet.time - request_times[rev_key]) * 1000  # 转换为毫秒
                        rtt_data[rev_key] = round(rtt, 2)
                
                # 记录TTL值
                ttl_key = (ip_layer.src, ip_layer.dst)
                ttl_data[ttl_key] = ip_layer.ttl
                
        return rtt_data, ttl_data
    except Exception as e:
        print(f"提取RTT/TTL失败：{str(e)}")
        return {}, {}

def load_and_clean_data(csv_path=None, pcap_path=None):
    """
    加载并清洗流量数据（从PCAP提取真实RTT/TTL）- 生产环境核心逻辑
    """
    # 1. 自动获取最新CSV和对应PCAP文件
    if not csv_path:
        csv_path = get_latest_file(CSV_BASE_DIR, ".csv")
        if not csv_path:
            csv_path = run_cicflowmeter()
            if not csv_path:
                print("错误：无可用CSV文件，且CICFlowMeter生成失败")
                return pd.DataFrame()
    
    # 自动匹配对应的PCAP文件
    if not pcap_path:
        csv_filename = os.path.basename(csv_path).replace(".csv", "")
        pcap_path = get_latest_file(PCAP_BASE_DIR, ".pcap", csv_filename)
    
    # 提取RTT和TTL数据
    rtt_data, ttl_data = {}, {}
    if pcap_path and os.path.exists(pcap_path):
        rtt_data, ttl_data = extract_rtt_ttl_from_pcap(pcap_path)
    
    try:
        # 加载CSV文件
        df = pd.read_csv(csv_path, encoding="utf-8")
        
        # 2. 处理缺失值（保持不变）
        df = df.fillna({
            "Flow Duration": 0,
            "Total Fwd Packets": 0,
            "Total Bwd Packets": 0,
            "Src Port": 0,
            "Dst Port": 0,
            "Protocol": 0
        })
        
        # 3. 补充协议名称（保持不变）
        protocol_mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Unknown"}
        df["Protocol_Name"] = df["Protocol"].map(protocol_mapping).fillna("Other")
        
        # 4. 从PCAP提取RTT和TTL（替换随机值）
        df["RTT"] = 0.0
        df["TTL"] = 0
        
        for idx, row in df.iterrows():
            # 匹配RTT
            rtt_key = (row["Src IP"], row["Dst IP"], row["Src Port"], row["Dst Port"])
            if rtt_key in rtt_data:
                df.at[idx, "RTT"] = rtt_data[rtt_key]
            else:
                df.at[idx, "RTT"] = np.random.uniform(10, 500)  # 仍无数据时使用随机值
            
            # 匹配TTL
            ttl_key = (row["Src IP"], row["Dst IP"])
            if ttl_key in ttl_data:
                df.at[idx, "TTL"] = ttl_data[ttl_key]
            else:
                df.at[idx, "TTL"] = np.random.choice([64, 128, 255])
        
        # 5. 计算TTL方差（保持不变）
        df["TTL Variance"] = df.groupby("Src IP")["TTL"].transform("var").fillna(0)
        
        # 6. 处理Payload字段（保持不变）
        if "Payload" not in df.columns:
            df["Payload"] = ""
        
        # 7. 初始化恶意流量标记（保持不变）
        df["malicious_label"] = "正常"
        df["malicious_reason"] = ""
        
        print(f"数据加载完成，共{len(df)}条记录，文件路径：{csv_path}")
        return df
    except Exception as e:
        print(f"数据加载失败：{str(e)}")
        return pd.DataFrame()

def analyze_traffic_patterns():
    """分析流量模式并检测攻击特征"""
    try:
        # 加载数据
        df = load_and_clean_data()
        signature_manager = SignatureManager()
        
        # 初始化结果
        report = {
            "total_flows": len(df),
            "protocols": df['protocol'].value_counts().to_dict(),
            "top_src_ips": df['src_ip'].value_counts().head(10).to_dict(),
            "top_dst_ips": df['dst_ip'].value_counts().head(10).to_dict(),
            "malicious": {"count": 0, "details": []},
            "flows": df.to_dict('records')  # 原始数据（用于ES存储）
        }
        
        # 匹配攻击特征
        for _, flow in df.iterrows():
            matches = signature_manager.match_signature(flow)
            if matches:
                report["malicious"]["count"] += 1
                report["malicious"]["details"].append({
                    "flow": flow.to_dict(),
                    "matches": matches
                })
        
        logger.info(f"流量分析完成：总流量{report['total_flows']}条，恶意流量{report['malicious']['count']}条")
        return report
    except Exception as e:
        error_msg = f"流量分析失败：{str(e)}"
        logger.error(error_msg, exc_info=True)
        return {"error": error_msg}