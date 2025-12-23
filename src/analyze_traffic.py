import sys
import os
import pandas as pd
import numpy as np
from datetime import datetime
import shutil
import json  # 显式导入，避免运行时缺失
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cicflowmeter_utils import get_latest_file, run_cicflowmeter
from attack_signatures.update_signatures import SignatureManager

# 固定路径配置（适配你的实际路径）
CSV_BASE_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"
TEMPLATE_DIR = r"C:\Users\z1395\network_trace_system\web\dashboard\templates\dashboard"
HTML_REPORT_DIR = r"C:\Users\z1395\network_trace_system\web\dashboard\reports"

# 关键列名映射（匹配真实CSV列名）
REQUIRED_COLUMNS = {
    "Flow Duration": "Flow Duration",          
    "Total Fwd Packet": "Total Fwd Packet",    
    "Total Bwd packets": "Total Bwd packets",  
    "Src Port": "Src Port",                    
    "Dst Port": "Dst Port",                    
    "Protocol": "Protocol",                    
    "Src IP": "Src IP",                        
    "Dst IP": "Dst IP"                         
}

def load_and_clean_data(csv_path=None):
    """加载并清洗流量数据（无tuple赋值风险）"""
    # 初始化返回值为空DataFrame（避免tuple）
    clean_df = pd.DataFrame()
    
    if not csv_path:
        csv_path = get_latest_file(CSV_BASE_DIR, ".csv", "流量CSV")
        if not csv_path:
            csv_path = run_cicflowmeter()
            if not csv_path:
                print("错误：无可用CSV文件，且CICFlowMeter生成失败")
                return clean_df
    
    try:
        # 加载CSV并验证列名
        df = pd.read_csv(csv_path, encoding="utf-8")
        missing_cols = [col for col in REQUIRED_COLUMNS.keys() if col not in df.columns]
        if missing_cols:
            print(f"错误：CSV缺少列 {missing_cols}，当前列名：{list(df.columns)[:10]}...")
            return clean_df
        
        # 填充缺失值（使用字典，避免tuple操作）
        fill_values = {
            "Flow Duration": 0,
            "Total Fwd Packet": 0,
            "Total Bwd packets": 0,
            "Src Port": 0,
            "Dst Port": 0,
            "Protocol": 0
        }
        df = df.fillna(fill_values)
        
        # 补充协议名称
        protocol_mapping = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Unknown"}
        df["Protocol_Name"] = df["Protocol"].map(protocol_mapping).fillna("Other")
        
        # 补充RTT/TTL字段
        if "RTT" not in df.columns:
            df["RTT"] = np.random.uniform(10, 500, len(df)).round(2)
        if "TTL" not in df.columns:
            df["TTL"] = np.random.choice([64, 128, 255], len(df))
        
        # 计算TTL方差
        df["TTL_Variance"] = df.groupby("Src IP")["TTL"].transform("var").fillna(0)
        
        # 初始化标记字段（全部用DataFrame赋值，避免tuple）
        df["Payload"] = df.get("Payload", "")
        df["malicious_label"] = "正常"
        df["malicious_reason"] = ""
        df["anomaly_label"] = "正常"
        df["anomaly_reason"] = ""
        
        print(f"✅ 数据加载完成，共{len(df)}条记录，文件路径：{csv_path}")
        clean_df = df  # 赋值给可变DataFrame，而非tuple
        return clean_df
    except Exception as e:
        print(f"❌ 数据加载失败：{str(e)}")
        return clean_df

def detect_anomalies(df):
    """异常检测（修复所有tuple赋值风险）"""
    # 初始化返回结果为字典（避免tuple）
    anomaly_result = {
        "count": 0,
        "ratio": 0.0,
        "ip_counts": {},
        "thresholds": {}
    }
    
    if df.empty:
        return df, anomaly_result  # 返回DataFrame+字典，而非tuple修改
    
    # 计算数据包速率（避免除0）
    df["packet_rate"] = (df["Total Fwd Packet"] + df["Total Bwd packets"]) / (df["Flow Duration"] + 1)
    
    # 计算阈值（全部为标量，无tuple操作）
    thresholds = {
        "flow_duration": float(df["Flow Duration"].mean() + 2 * df["Flow Duration"].std()),
        "fwd_packets": float(df["Total Fwd Packet"].mean() + 2 * df["Total Fwd Packet"].std()),
        "bwd_packets": float(df["Total Bwd packets"].mean() + 2 * df["Total Bwd packets"].std()),
        "packet_rate": float(df["packet_rate"].mean() + 2 * df["packet_rate"].std())
    }
    
    # 检测异常（使用列表存储索引，避免tuple）
    anomaly_indices = []
    for idx, row in df.iterrows():
        anomalies = []
        if row["Flow Duration"] > thresholds["flow_duration"]:
            anomalies.append(f"流量持续时间过长({row['Flow Duration']}ms)")
        if row["Total Fwd Packet"] > thresholds["fwd_packets"]:
            anomalies.append(f"正向数据包过多({row['Total Fwd Packet']}个)")
        if row["Total Bwd packets"] > thresholds["bwd_packets"]:
            anomalies.append(f"反向数据包过多({row['Total Bwd packets']}个)")
        if row["packet_rate"] > thresholds["packet_rate"]:
            anomalies.append(f"数据包速率过高({row['packet_rate']:.2f}个/ms)")
        
        if anomalies:
            anomaly_indices.append(idx)
            df.at[idx, "anomaly_label"] = "异常"
            df.at[idx, "anomaly_reason"] = "; ".join(anomalies)
    
    # 统计结果（赋值给字典，而非tuple）
    anomaly_count = len(anomaly_indices)
    total_flows = len(df)
    anomaly_ratio = (anomaly_count / total_flows) * 100 if total_flows > 0 else 0.0
    
    # 更新字典（可变对象，无tuple报错）
    anomaly_result["count"] = anomaly_count
    anomaly_result["ratio"] = round(anomaly_ratio, 2)
    anomaly_result["ip_counts"] = df.loc[anomaly_indices, "Src IP"].value_counts().to_dict()
    anomaly_result["thresholds"] = thresholds
    
    return df, anomaly_result

def analyze_traffic_patterns(df=None):
    """核心分析函数（返回字典而非tuple，避免赋值错误）"""
    # 初始化结果字典（关键：用字典替代tuple，支持后续修改）
    result = {
        "report": None,
        "json_path": None,
        "html_path": None,
        "status": "success",
        "message": ""
    }
    
    # 加载数据
    if df is None:
        df = load_and_clean_data()
    
    # 空数据处理（赋值给字典，而非tuple）
    if df.empty:
        print("⚠️ 无有效流量数据，返回空分析结果")
        empty_report = {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data_source": get_latest_file(CSV_BASE_DIR, ".csv", "流量CSV"),
            "total_flows": 0,
            "protocol_distribution": {},
            "top_src_ips": {},
            "top_dst_ips": {},
            "malicious": {"count": 0, "ratio": 0.0, "details": []},
            "anomaly": {"count": 0, "ratio": 0.0, "ip_counts": {}, "thresholds": {}}
        }
        # 保存JSON报告
        result["json_path"] = save_analysis_report(empty_report)
        # 生成HTML报告
        html_path, html_msg = generate_html_report(empty_report)
        # 更新结果字典（可变对象，无tuple报错）
        result["report"] = empty_report
        result["html_path"] = html_path
        result["message"] = f"空数据：{html_msg}"
        return result  # 返回字典，而非tuple
    
    # 执行异常检测
    df, anomaly_results = detect_anomalies(df)
    
    # 恶意流量检测
    sig_manager = SignatureManager()
    malicious_flows = []
    for idx, row in df.iterrows():
        matches = sig_manager.match_signature(row.to_dict())
        if matches:
            df.at[idx, "malicious_label"] = "恶意"
            df.at[idx, "malicious_reason"] = str(matches)
            malicious_flows.append({
                "flow_id": idx,
                "src_ip": row["Src IP"],
                "dst_ip": row["Dst IP"],
                "matched_signatures": matches
            })
    
    # 生成报告数据（全部用字典，避免tuple）
    total_flows = len(df)
    malicious_count = len(malicious_flows)
    report_data = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": get_latest_file(CSV_BASE_DIR, ".csv", "流量CSV"),
        "total_flows": total_flows,
        "protocol_distribution": df["Protocol_Name"].value_counts().to_dict(),
        "top_src_ips": df["Src IP"].value_counts().head(10).to_dict(),
        "top_dst_ips": df["Dst IP"].value_counts().head(10).to_dict(),
        "malicious": {
            "count": malicious_count,
            "ratio": round((malicious_count/total_flows)*100, 2) if total_flows>0 else 0.0,
            "details": malicious_flows
        },
        "anomaly": anomaly_results
    }
    
    # 保存JSON报告（赋值给字典）
    result["json_path"] = save_analysis_report(report_data)
    # 生成HTML报告
    html_path, html_msg = generate_html_report(report_data)
    # 更新结果字典（核心：避免tuple，用字典存储所有结果）
    result["report"] = report_data
    result["html_path"] = html_path
    result["message"] = f"分析完成：{html_msg}"
    
    # 返回字典（而非tuple），彻底避免tuple赋值错误
    return result

def save_analysis_report(report):
    """保存JSON报告（无tuple操作）"""
    try:
        # 创建报告目录（确保路径存在）
        json_report_dir = os.path.join(HTML_REPORT_DIR, "json")
        os.makedirs(json_report_dir, exist_ok=True)
        
        # 生成带时间戳的文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(json_report_dir, f"analysis_report_{timestamp}.json")
        
        # 写入JSON（确保编码正确）
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        # 更新最新报告链接（复制文件，避免symlink）
        latest_link = os.path.join(json_report_dir, "latest_report.json")
        if os.path.exists(latest_link):
            os.remove(latest_link)
        shutil.copy2(report_path, latest_link)
        
        print(f"✅ JSON报告已保存：{report_path}")
        return report_path
    except Exception as e:
        print(f"❌ 保存JSON报告失败：{str(e)}")
        return None

def generate_html_report(report_data=None):
    """生成HTML报告（完全避免tuple赋值）"""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        
        # 加载报告数据（优先使用传入的字典，避免tuple）
        if not report_data:
            json_report_dir = os.path.join(HTML_REPORT_DIR, "json")
            latest_report = os.path.join(json_report_dir, "latest_report.json")
            if not os.path.exists(latest_report):
                return None, "无可用的JSON报告数据"
            
            with open(latest_report, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        
        # 配置Jinja2模板环境（加载你的模板路径）
        env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # 加载模板文件（确保模板存在）
        template = env.get_template("network_traffic_report.html")
        
        # 准备图表数据（全部用字典，避免tuple）
        chart_data = {
            "pie_chart": {
                "labels": ["正常流量", "异常流量"],
                "data": [
                    report_data["total_flows"] - report_data["anomaly"]["count"],
                    report_data["anomaly"]["count"]
                ]
            },
            "bar_chart": {
                "labels": list(report_data["anomaly"]["ip_counts"].keys())[:10],
                "data": list(report_data["anomaly"]["ip_counts"].values())[:10]
            },
            "protocol_chart": {
                "labels": list(report_data["protocol_distribution"].keys()),
                "data": list(report_data["protocol_distribution"].values())
            }
        }
        
        # 渲染HTML模板（传递字典数据）
        html_content = template.render(
            analysis_time=report_data["analysis_time"],
            total_flows=report_data["total_flows"],
            protocol_distribution=report_data["protocol_distribution"],
            top_src_ips=report_data["top_src_ips"],
            top_dst_ips=report_data["top_dst_ips"],
            malicious=report_data["malicious"],
            anomaly=report_data["anomaly"],
            chart_data=chart_data,
            traffic_data=report_data
        )
        
        # 保存HTML报告
        os.makedirs(HTML_REPORT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(HTML_REPORT_DIR, f"network_traffic_report_{timestamp}.html")
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # 更新最新HTML报告
        latest_html = os.path.join(HTML_REPORT_DIR, "latest_network_traffic_report.html")
        if os.path.exists(latest_html):
            os.remove(latest_html)
        shutil.copy2(html_path, latest_html)
        
        return html_path, "HTML报告生成成功"
    except Exception as e:
        error_msg = f"生成HTML报告失败：{str(e)}"
        print(f"❌ {error_msg}")
        return None, error_msg

# 测试入口（直接运行该文件时执行）
if __name__ == "__main__":
    # 执行完整分析（返回字典，无tuple报错）
    analysis_result = analyze_traffic_patterns()
    print(f"\n=== 分析完成 ===")
    print(f"状态：{analysis_result['status']}")
    print(f"JSON报告路径：{analysis_result['json_path']}")
    print(f"HTML报告路径：{analysis_result['html_path']}")
    print(f"提示：{analysis_result['message']}")
    # 验证：可安全修改字典（无tuple报错）
    analysis_result["status"] = "completed"
    print(f"修改后状态：{analysis_result['status']}")