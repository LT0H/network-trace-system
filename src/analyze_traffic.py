import os
import pandas as pd
import glob
import logging
from datetime import datetime
from attack_signatures.update_signatures import SignatureManager

# 初始化日志
logger = logging.getLogger("traffic_analyzer")

def load_and_clean_data():
    """加载并清洗CICFlowMeter输出的流量数据"""
    from main import CICFLOWMETER_OUTPUT_DIR  # 从主配置导入路径
    
    # 验证输出目录
    if not os.path.exists(CICFLOWMETER_OUTPUT_DIR):
        error_msg = f"CICFlowMeter输出目录不存在：{CICFLOWMETER_OUTPUT_DIR}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    # 获取最新CSV文件
    csv_files = glob.glob(os.path.join(CICFLOWMETER_OUTPUT_DIR, "*.csv"))
    if not csv_files:
        error_msg = f"未找到流量数据文件：{CICFLOWMETER_OUTPUT_DIR}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    latest_file = max(csv_files, key=os.path.getmtime)
    if os.path.getsize(latest_file) < 1024:  # 过滤空文件
        error_msg = f"流量数据文件为空：{latest_file}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # 读取并清洗数据
    try:
        df = pd.read_csv(
            latest_file,
            parse_dates=['Timestamp'],
            on_bad_lines='skip'  # 跳过错误行
        )
        
        # 字段重命名（统一格式）
        rename_map = {
            'Src IP': 'src_ip',
            'Dst IP': 'dst_ip',
            'Src Port': 'src_port',
            'Dst Port': 'dst_port',
            'Protocol': 'protocol',
            'Timestamp': 'timestamp',
            'Flow Duration': 'flow_duration',
            'Total Fwd Packets': 'fwd_packets',
            'Total Backward Packets': 'bwd_packets'
        }
        df = df.rename(columns=rename_map)
        
        # 计算总数据包数
        df['packet_count'] = df['fwd_packets'] + df['bwd_packets']
        
        # 保留必要字段
        required_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
                           'timestamp', 'flow_duration', 'packet_count']
        df = df[required_columns].dropna(subset=['src_ip', 'dst_ip'])
        
        logger.info(f"成功加载流量数据：{latest_file}，共{len(df)}条记录")
        return df
    except Exception as e:
        error_msg = f"数据清洗失败：{str(e)}"
        logger.error(error_msg, exc_info=True)
        raise

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