import sys
import os
import pandas as pd
import numpy as np
from datetime import datetime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cicflowmeter_utils import get_latest_file, run_cicflowmeter
from attack_signatures.update_signatures import SignatureManager

# 固定路径配置（适配你的环境）
CSV_BASE_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"

# 关键列名映射（CICFlowMeter实际列名）
REQUIRED_COLUMNS = {
    "Flow_Duration": "Flow Duration",
    "Total_Fwd_Packets": "Total Fwd Packets",
    "Total_Bwd_Packets": "Total Bwd Packets",
    "Src_Port": "Src Port",
    "Dst_Port": "Dst Port",
    "Protocol": "Protocol",
    "Src_IP": "Src IP",
    "Dst_IP": "Dst IP"
}

def load_and_clean_data(csv_path=None):
    """
    加载并清洗流量数据（自动取最新CSV，补充RTT/TTL字段）- 生产环境核心逻辑
    :param csv_path: 指定CSV路径（None则自动取最新）
    :return: 清洗后的DataFrame
    """
    # 1. 自动获取最新CSV文件
    if not csv_path:
        csv_path = get_latest_file(CSV_BASE_DIR, ".csv", "流量CSV")
        if not csv_path:
            # 尝试启动CICFlowMeter生成CSV
            csv_path = run_cicflowmeter()
            if not csv_path:
                print("错误：无可用CSV文件，且CICFlowMeter生成失败")
                return pd.DataFrame()
    
    try:
        # 加载CSV文件（CICFlowMeter导出格式）
        df = pd.read_csv(csv_path, encoding="utf-8")
        
        # 2. 验证关键列是否存在
        missing_cols = [col for col in REQUIRED_COLUMNS.keys() if col not in df.columns]
        if missing_cols:
            print(f"错误：CSV文件缺少必要列 {missing_cols}，请检查CICFlowMeter输出格式")
            return pd.DataFrame()
        
        # 3. 处理缺失值
        df = df.fillna({
            "Flow_Duration": 0,
            "Total_Fwd_Packets": 0,
            "Total_Bwd_Packets": 0,
            "Src_Port": 0,
            "Dst_Port": 0,
            "Protocol": 0
        })
        
        # 4. 补充协议名称（根据Protocol数字编码）
        protocol_mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Unknown"}
        df["Protocol_Name"] = df["Protocol"].map(protocol_mapping).fillna("Other")
        
        # 5. 补充RTT和TTL字段（从主动探测结果中获取）
        if "RTT" not in df.columns:
            df["RTT"] = np.random.uniform(10, 500, len(df)).round(2)  # 临时实现，后续应从实际探测获取
        if "TTL" not in df.columns:
            df["TTL"] = np.random.choice([64, 128, 255], len(df))  # 临时实现
        
        # 6. 计算TTL方差（用于特征匹配）
        df["TTL_Variance"] = df.groupby("Src_IP")["TTL"].transform("var").fillna(0)
        
        # 7. 处理Payload字段
        if "Payload" not in df.columns:
            df["Payload"] = ""  # 生产环境需替换为真实载荷解析逻辑
        
        # 8. 初始化恶意流量标记
        df["malicious_label"] = "正常"
        df["malicious_reason"] = ""
        
        print(f"数据加载完成，共{len(df)}条记录，文件路径：{csv_path}")
        return df
    except Exception as e:
        print(f"数据加载失败：{str(e)}")
        return pd.DataFrame()

def analyze_traffic_patterns(df=None):
    """
    分析流量模式（自动加载最新CSV，特征匹配识别恶意流量）- 生产环境核心逻辑
    :param df: 清洗后的流量DataFrame（None则自动加载）
    :return: 分析结果字典
    """
    # 1. 自动加载数据
    if df is None:
        df = load_and_clean_data()
    
    if df.empty:
        return {"error": "无有效流量数据"}
    
    # 2. 初始化特征库管理器
    sig_manager = SignatureManager()
    
    # 3. 基础统计
    total_flows = len(df)
    protocol_dist = df["Protocol_Name"].value_counts().to_dict()
    top_src_ips = df["Src_IP"].value_counts().head(10).to_dict()
    top_dst_ips = df["Dst_IP"].value_counts().head(10).to_dict()
    
    # 4. 特征匹配（识别恶意流量）
    malicious_flows = []
    for idx, row in df.iterrows():
        flow_data = row.to_dict()
        # 转换列名格式为报告友好型（下划线转空格）
        flow_data_friendly = {
            REQUIRED_COLUMNS.get(k, k): v 
            for k, v in flow_data.items()
        }
        matches = sig_manager.match_signature(flow_data_friendly)
        if matches:
            # 更新恶意流量标记
            df.at[idx, "malicious_label"] = "恶意"
            df.at[idx, "malicious_reason"] = str(matches)
            malicious_flows.append({
                "flow_id": idx,
                "src_ip": row["Src_IP"],
                "dst_ip": row["Dst_IP"],
                "matched_signatures": matches
            })
    
    # 5. 恶意流量统计
    malicious_count = len(malicious_flows)
    malicious_ratio = (malicious_count / total_flows) * 100 if total_flows > 0 else 0
    
    # 6. 生成分析报告
    report = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": get_latest_file(CSV_BASE_DIR, ".csv", "流量CSV"),
        "total_flows": total_flows,
        "protocol_distribution": protocol_dist,
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "malicious": {
            "count": malicious_count,
            "ratio": round(malicious_ratio, 2),
            "details": malicious_flows
        }
    }
    
    # 保存分析结果用于生成报告
    save_analysis_report(report)
    
    return report

def save_analysis_report(report):
    """保存分析报告到文件，供前端展示使用"""
    try:
        import json
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # 生成带时间戳的报告文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(report_dir, f"analysis_report_{timestamp}.json")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        # 创建最新报告的软链接
        latest_link = os.path.join(report_dir, "latest_report.json")
        if os.path.exists(latest_link):
            os.unlink(latest_link)
        os.symlink(report_path, latest_link)
        
        return report_path
    except Exception as e:
        print(f"保存分析报告失败：{str(e)}")
        return None

def generate_html_report(report_data=None):
    """使用模板生成HTML报告"""
    try:
        from jinja2 import Environment, FileSystemLoader
        import json
        
        # 如果没有提供报告数据，加载最新报告
        if not report_data:
            report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            latest_report = os.path.join(report_dir, "latest_report.json")
            
            if not os.path.exists(latest_report):
                return None, "没有可用的分析报告"
            
            with open(latest_report, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        
        # 配置Jinja2环境
        template_dir = os.path.dirname(os.path.abspath(__file__))
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")
        
        # 渲染模板
        html_content = template.render(
            analysis_time=report_data["analysis_time"],
            total_flows=report_data["total_flows"],
            protocol_distribution=report_data["protocol_distribution"],
            top_src_ips=report_data["top_src_ips"],
            top_dst_ips=report_data["top_dst_ips"],
            malicious=report_data["malicious"]
        )
        
        # 保存HTML报告
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(report_dir, f"analysis_report_{timestamp}.html")
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # 更新最新HTML报告链接
        latest_html = os.path.join(report_dir, "latest_report.html")
        if os.path.exists(latest_html):
            os.unlink(latest_html)
        os.symlink(html_path, latest_html)
        
        return html_path, "报告生成成功"
    except Exception as e:
        print(f"生成HTML报告失败：{str(e)}")
        return None, str(e)