import sys
import os
import socket
import whois
import traceback
import pandas as pd
from ip2geotools.databases.noncommercial import DbIpCity
from ip2geotools.errors import AddressNotFoundError
from scipy.spatial.distance import cosine  # 余弦相似度计算
import numpy as np
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cicflowmeter_utils import get_latest_file

# 固定路径配置（适配你的环境）
IP_DB_PATH = r"C:\Users\z1395\network_trace_system\ip_data\qqwry.dat"
CSV_BASE_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"

class IPTracker:
    def __init__(self):
        """初始化IP轨迹追踪器 - 生产环境核心逻辑"""
        self.ip_db_path = IP_DB_PATH

    def get_geo_location(self, ip):
        """获取IP地理位置（优先调用免费API）- 生产环境核心逻辑"""
        try:
            # 过滤内网IP
            if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
                return {
                    "country": "内网",
                    "region": "内网",
                    "city": "内网",
                    "latitude": 0.0,
                    "longitude": 0.0,
                    "is_internal": True
                }
            
            # 使用DbIpCity免费API查询
            response = DbIpCity.get(ip, api_key="free")
            return {
                "country": response.country,
                "region": response.region,
                "city": response.city,
                "latitude": response.latitude,
                "longitude": response.longitude,
                "is_internal": False
            }
        except AddressNotFoundError:
            return {"error": f"IP {ip} 未找到地理位置", "is_internal": False}
        except Exception as e:
            return {"error": f"获取地理位置失败：{str(e)}", "is_internal": False}

    def get_whois_info(self, ip):
        """获取IP的WHOIS信息（注册商、所属机构等）- 生产环境核心逻辑"""
        try:
            # 过滤内网IP
            if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
                return {"error": "内网IP无WHOIS信息"}
            
            w = whois.whois(ip)
            return {
                "registrar": w.registrar if w.registrar else "未知",
                "org": w.org if w.org else "未知",
                "country": w.country if w.country else "未知",
                "created": str(w.created) if w.created else "未知",
                "updated": str(w.updated) if w.updated else "未知",
                "expiration": str(w.expiration) if w.expiration else "未知",
                "name_servers": w.name_servers if w.name_servers else []
            }
        except Exception as e:
            return {"error": f"获取WHOIS信息失败：{str(e)}"}

    def resolve_domain(self, ip):
        """IP反解析域名（反向DNS）- 生产环境核心逻辑"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {"domain": hostname}
        except socket.herror:
            return {"error": f"IP {ip} 无反向解析记录"}
        except Exception as e:
            return {"error": f"反向解析失败：{str(e)}"}

    def ip_fingerprint(self, ip, flow_df=None):
        """
        生成IP指纹（基于流量特征）- 生产环境核心逻辑
        :param ip: 目标IP
        :param flow_df: 流量数据DataFrame（None则自动加载最新）
        :return: IP指纹字典
        """
        # 自动加载最新流量数据
        if flow_df is None:
            from .analyze_traffic import load_and_clean_data
            flow_df = load_and_clean_data()
        
        try:
            # 筛选该IP的流量数据
            ip_flows = flow_df[(flow_df["Src IP"] == ip) | (flow_df["Dst IP"] == ip)]
            if len(ip_flows) == 0:
                return {"error": f"无IP {ip} 的流量数据"}
            
            # 提取指纹特征
            src_flows = flow_df[flow_df["Src IP"] == ip]
            dst_flows = flow_df[flow_df["Dst IP"] == ip]
            
            fingerprint = {
                "ip": ip,
                "total_flows": len(ip_flows),
                "as_src_count": len(src_flows),
                "as_dst_count": len(dst_flows),
                "avg_ttl": round(ip_flows["TTL"].mean(), 2) if "TTL" in ip_flows.columns else 0,
                "ttl_std": round(ip_flows["TTL"].std(), 2) if "TTL" in ip_flows.columns else 0,
                "protocol_preference": ip_flows["Protocol_Name"].mode().values[0] if "Protocol_Name" in ip_flows.columns else "未知",
                "common_ports": {
                    "src_ports": src_flows["Src Port"].value_counts().head(5).to_dict() if "Src Port" in src_flows.columns else {},
                    "dst_ports": dst_flows["Dst Port"].value_counts().head(5).to_dict() if "Dst Port" in dst_flows.columns else {}
                },
                "avg_rtt": round(ip_flows["RTT"].mean(), 2) if "RTT" in ip_flows.columns else 0,
                "flow_duration_stats": {
                    "avg": round(ip_flows["Flow Duration"].mean(), 2) if "Flow Duration" in ip_flows.columns else 0,
                    "max": ip_flows["Flow Duration"].max() if "Flow Duration" in ip_flows.columns else 0,
                    "min": ip_flows["Flow Duration"].min() if "Flow Duration" in ip_flows.columns else 0
                }
            }
            return fingerprint
        except Exception as e:
            return {"error": f"生成IP指纹失败：{str(e)}", "traceback": traceback.format_exc()}

    def fingerprint_similarity(self, fp1, fp2):
        """计算两个IP指纹的余弦相似度 - 生产环境核心逻辑"""
        try:
            # 提取数值特征
            features1 = [
                fp1["avg_ttl"], fp1["ttl_std"], fp1["avg_rtt"],
                fp1["flow_duration_stats"]["avg"], fp1["flow_duration_stats"]["max"],
                fp1["as_src_count"], fp1["as_dst_count"]
            ]
            features2 = [
                fp2["avg_ttl"], fp2["ttl_std"], fp2["avg_rtt"],
                fp2["flow_duration_stats"]["avg"], fp2["flow_duration_stats"]["max"],
                fp2["as_src_count"], fp2["as_dst_count"]
            ]
            
            # 标准化特征（避免量纲影响）
            features1 = np.array(features1) / (np.max(features1) + 1e-8)
            features2 = np.array(features2) / (np.max(features2) + 1e-8)
            
            # 计算余弦相似度（1 - 余弦距离）
            similarity = 1 - cosine(features1, features2)
            return round(similarity, 4)
        except Exception as e:
            return {"error": f"计算相似度失败：{str(e)}"}

    def track_ip_trajectory(self, ip, flow_df=None):
        """
        追踪IP通信轨迹 - 生产环境核心逻辑
        :param ip: 目标IP
        :param flow_df: 流量数据DataFrame（None则自动加载）
        :return: 轨迹字典
        """
        # 自动加载数据
        if flow_df is None:
            from .analyze_traffic import load_and_clean_data
            flow_df = load_and_clean_data()
        
        try:
            # 1. 获取目标IP基础信息
            base_info = {
                "ip": ip,
                "geo": self.get_geo_location(ip),
                "whois": self.get_whois_info(ip),
                "reverse_dns": self.resolve_domain(ip),
                "fingerprint": self.ip_fingerprint(ip, flow_df)
            }
            
            # 2. 提取关联IP
            related_ips = pd.concat([
                flow_df[flow_df["Src IP"] == ip]["Dst IP"],
                flow_df[flow_df["Dst IP"] == ip]["Src IP"]
            ]).unique()
            
            # 3. 分析每个关联IP的通信信息
            trajectory = []
            for related_ip in related_ips[:50]:  # 生产环境限制返回数量
                # 筛选双向通信数据
                comm_flows = flow_df[
                    ((flow_df["Src IP"] == ip) & (flow_df["Dst IP"] == related_ip)) |
                    ((flow_df["Src IP"] == related_ip) & (flow_df["Dst IP"] == ip))
                ]
                
                trajectory.append({
                    "related_ip": related_ip,
                    "geo": self.get_geo_location(related_ip),
                    "communication_count": len(comm_flows),
                    "first_communication": comm_flows["timestamp"].min() if "timestamp" in comm_flows.columns else "未知",
                    "last_communication": comm_flows["timestamp"].max() if "timestamp" in comm_flows.columns else "未知",
                    "protocol_dist": comm_flows["Protocol_Name"].value_counts().to_dict() if "Protocol_Name" in comm_flows.columns else {}
                })
            
            # 4. 按通信频次排序
            trajectory.sort(key=lambda x: x["communication_count"], reverse=True)
            
            return {
                "target_ip_info": base_info,
                "related_ips_count": len(related_ips),
                "trajectory": trajectory,
                "track_time": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return {"error": f"追踪IP轨迹失败：{str(e)}", "traceback": traceback.format_exc()}