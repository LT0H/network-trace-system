import os
import subprocess
import time
from pathlib import Path
import glob

# 固定路径配置（适配你的环境）
CICFLOWMETER_JAR_PATH = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
PCAP_DIR = r"C:\Users\z1395\network_trace_system\catched_data"
CSV_OUTPUT_DIR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\data\daily"

def get_latest_file(directory, file_pattern, desc):
    """
    获取目录下最新的指定类型文件
    :param directory: 目录路径
    :param file_pattern: 文件模式，如".csv"
    :param desc: 文件描述，用于日志
    :return: 最新文件的路径或None
    """
    if not os.path.exists(directory):
        print(f"❌ {desc}目录不存在：{directory}")
        return None
    
    # 获取目录下所有符合模式的文件
    files = []
    for filename in os.listdir(directory):
        if filename.endswith(file_pattern):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                files.append(file_path)
    
    if not files:
        print(f"❌ 在{directory}中未找到{desc}文件")
        return None
    
    # 按修改时间排序，取最新的
    files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    latest_file = files[0]
    
    print(f"✅ 找到最新的{desc}文件：{latest_file}")
    return latest_file

def run_cicflowmeter(duration=60):
    """
    运行CICFlowMeter捕获流量并生成CSV文件
    :param duration: 捕获时长（秒）
    :return: 生成的CSV文件路径或None
    """
    # 检查必要文件
    if not os.path.exists(CICFLOWMETER_JAR):
        print(f"❌ CICFlowMeter JAR文件不存在：{CICFLOWMETER_JAR}")
        return None
    
    if not os.path.exists(JNETPCAP_DLL_DIR):
        print(f"❌ JNetPcap目录不存在：{JNETPCAP_DLL_DIR}")
        return None
    
    # 创建输出目录
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    
    # 记录启动前的最新文件，用于后续判断新生成的文件
    pre_files = [f for f in os.listdir(CSV_OUTPUT_DIR) if f.endswith(".csv")]
    
    # 构造启动命令
    cmd = [
        "java",
        f"-Djava.library.path={JNETPCAP_DLL_DIR}",
        "-Dfile.encoding=UTF-8",
        "-jar", CICFLOWMETER_JAR,
        "-i", "all",  # 监控所有接口
        "-o", CSV_OUTPUT_DIR  # 输出目录
    ]
    
    process = None
    try:
        # 启动CICFlowMeter
        print(f"🚀 启动CICFlowMeter，将运行{duration}秒...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
        
        # 运行指定时长
        time.sleep(duration)
        
        # 停止进程
        if process and process.poll() is None:
            # 尝试优雅终止
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # 强制终止
                process.kill()
        
        # 查找新生成的CSV文件
        post_files = [f for f in os.listdir(CSV_OUTPUT_DIR) if f.endswith(".csv")]
        new_files = [f for f in post_files if f not in pre_files]
        
        if new_files:
            # 按修改时间排序，取最新的
            new_files.sort(key=lambda x: os.path.getmtime(os.path.join(CSV_OUTPUT_DIR, x)), reverse=True)
            latest_csv = os.path.join(CSV_OUTPUT_DIR, new_files[0])
            print(f"✅ CICFlowMeter已生成CSV文件：{latest_csv}")
            return latest_csv
        else:
            print("❌ CICFlowMeter未生成新的CSV文件")
            return None
            
    except Exception as e:
        print(f"❌ 运行CICFlowMeter时出错：{str(e)}")
        if process:
            try:
                process.kill()
            except:
                pass
        return None

def stop_all_cicflowmeter():
    """停止所有CICFlowMeter进程"""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] == 'java.exe' and CICFLOWMETER_JAR in ' '.join(proc.info['cmdline']):
                    proc.kill()
                    print(f"🛑 已终止CICFlowMeter进程（PID：{proc.info['pid']}）")
            except:
                continue
    except Exception as e:
        print(f"❌ 停止CICFlowMeter进程时出错：{str(e)}")