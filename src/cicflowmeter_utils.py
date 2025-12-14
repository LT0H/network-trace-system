import os
import subprocess
import time
from pathlib import Path
import glob

# 固定路径配置（适配你的环境）
CICFLOWMETER_JAR_PATH = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
PCAP_DIR = r"C:\Users\z1395\network_trace_system\catched_data"
CSV_OUTPUT_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"

def get_latest_file(dir_path, file_suffix):
    """
    获取指定目录下最新的文件（按修改时间排序）
    :param dir_path: 目录路径
    :param file_suffix: 文件后缀（如.pcap、.csv）
    :return: 最新文件的绝对路径，无文件返回None
    """
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        return None
    
    # 匹配所有指定后缀的文件
    file_pattern = os.path.join(dir_path, f"*{file_suffix}")
    files = glob.glob(file_pattern)
    
    if not files:
        return None
    
    # 按修改时间排序，取最新的
    latest_file = max(files, key=os.path.getmtime)
    return latest_file

def run_cicflowmeter(pcap_file_path=None):
    """
    启动CICFlowMeter生成流量CSV文件
    :param pcap_file_path: 指定PCAP文件路径（None则自动取catched_data下最新PCAP）
    :return: 生成的CSV文件路径，失败返回None
    """
    # 1. 校验JAR文件是否存在
    if not os.path.exists(CICFLOWMETER_JAR_PATH):
        print(f"错误：CICFlowMeter JAR文件不存在 - {CICFLOWMETER_JAR_PATH}")
        return None
    
    # 2. 确定PCAP文件（自动取最新或指定）
    if not pcap_file_path:
        pcap_file_path = get_latest_file(PCAP_DIR, ".pcap")
        if not pcap_file_path:
            print("错误：catched_data目录下无PCAP文件")
            return None
    
    # 3. 创建输出目录
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    
    # 4. 构造启动命令（Java运行JAR，导入PCAP生成CSV）
    cmd = [
        "java", "-jar", CICFLOWMETER_JAR_PATH,
        "-i", pcap_file_path,  # 输入PCAP文件
        "-o", CSV_OUTPUT_DIR   # 输出CSV目录
    ]
    
    try:
        # 启动CICFlowMeter，等待执行完成
        print(f"启动CICFlowMeter，命令：{' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            timeout=300  # 超时时间5分钟
        )
        
        if result.returncode != 0:
            print(f"CICFlowMeter执行失败：{result.stderr}")
            return None
        
        # 5. 获取生成的最新CSV文件
        time.sleep(2)  # 等待文件写入完成
        latest_csv = get_latest_file(CSV_OUTPUT_DIR, ".csv")
        if latest_csv:
            print(f"成功生成CSV文件：{latest_csv}")
            return latest_csv
        else:
            print("错误：CICFlowMeter执行完成但未生成CSV文件")
            return None
    except subprocess.TimeoutExpired:
        print("错误：CICFlowMeter执行超时（超过5分钟）")
        return None
    except Exception as e:
        print(f"错误：启动CICFlowMeter异常 - {str(e)}")
        return None