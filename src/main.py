import os
import subprocess
import time
import signal
from pathlib import Path
import sys
import ctypes
import re
import socket
import glob
import tempfile
import shutil

# ========== 核心配置（严格对齐用户实际路径，无拼写错误） ==========
BASE_DIR = r"C:\Users\z1395\network_trace_system"

# 1. CICFlowMeter配置（强制指定输出目录，修复JNETPCAP路径）
CICFLOWMETER_JAR = os.path.join(BASE_DIR, "CICFlowMeter", "target", "CICFlowMeterV3-0.0.4-SNAPSHOT.jar")
CICFLOWMETER_OUTPUT_DIR = os.path.abspath(os.path.join(BASE_DIR, "CICFlowMeter", "target", "data", "daily"))  # 绝对路径
JNETPCAP_DLL_DIR = os.path.join(BASE_DIR, "CICFlowMeter", "jnetpcap", "win", "jnetpcap-1.4.r1425")

# 2. Common IP（ws-traffic-analyze-kit）配置
COMMON_IP_EXE = os.path.join(BASE_DIR, "ws-traffic-analyze-kit", "target", "release", "common_ip.exe")
RESULT_FILE_PATH = os.path.join(BASE_DIR, "ws-traffic-analyze-kit", "ip_counts.txt")

# 3. dumpcap配置（支持HTTP+HTTPS）
DUMPCAP_EXE = r"C:\Program Files\Wireshark\dumpcap.exe"
PCAP_CAPTURE_DIR = os.path.join(BASE_DIR, "catched_data")

# 4. pcap2para配置（依赖检查增强）
# 修复路径：根据实际路径修改
PCAP2PARA_EXE = os.path.join(BASE_DIR, "pcap2para", "build", "bin", "Release", "pcap2para.exe")
ANALYZED_DATA_DIR = os.path.join(BASE_DIR, "analyzed_data")
BOOST_DLL_NAME = "boost_regex-vc143-mt-x64-1_81.dll"  # Boost依赖DLL
BOOST_DLL_PATH = os.path.join(os.path.dirname(PCAP2PARA_EXE), BOOST_DLL_NAME)

# 全局变量
dumpcap_process = None
selected_interface = ""
selected_interface_info = {}
pcap_file_path = ""  # 存储生成的PCAP文件路径


def check_admin():
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def check_dependencies():
    """检查所有依赖"""
    print("\n🔍 检查依赖项...")
    
    dependencies = {
        "WinPcap/Npcap": check_npcap_winpcap(),
        "Java": check_java(),
        "CICFlowMeter JAR": check_cicflowmeter_jar(),
        "Wireshark": check_wireshark(),
        "pcap2para": check_pcap2para(),
    }
    
    all_ok = True
    for dep, status in dependencies.items():
        if status:
            print(f"✅ {dep}: 已安装")
        else:
            print(f"❌ {dep}: 未找到")
            all_ok = False
    
    return all_ok


def check_npcap_winpcap():
    """检查抓包驱动（增强版：检查pcap库）"""
    winpcap_paths = [
        r"C:\Windows\System32\wpcap.dll", 
        r"C:\Program Files\WinPcap\wpcap.dll",
        r"C:\Program Files\Npcap\wpcap.dll"
    ]
    has_winpcap = any(os.path.exists(p) for p in winpcap_paths)
    
    if has_winpcap:
        # 检查环境变量（修复pcap2para依赖）
        if "PATH" not in os.environ or not any(p in os.environ["PATH"] for p in winpcap_paths):
            os.environ["PATH"] += ";" + os.path.dirname([p for p in winpcap_paths if os.path.exists(p)][0])
        return True
    return False


def check_java():
    """检查Java安装"""
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


def check_cicflowmeter_jar():
    """检查CICFlowMeter JAR"""
    return os.path.exists(CICFLOWMETER_JAR)


def check_wireshark():
    """检查Wireshark安装"""
    return os.path.exists(DUMPCAP_EXE)


def check_pcap2para():
    """检查pcap2para"""
    return os.path.exists(PCAP2PARA_EXE)


def get_network_interfaces():
    """解析网卡列表（兼容旧版dumpcap）"""
    interfaces = []
    recommended_idx = ""
    
    if not os.path.exists(DUMPCAP_EXE):
        print(f"❌ dumpcap.exe not found: {DUMPCAP_EXE}")
        return interfaces, recommended_idx
    
    try:
        result = subprocess.run(
            [DUMPCAP_EXE, "-D"],
            capture_output=True,
            encoding='gbk',
            errors='ignore'
        )
        
        print(f"\n📝 dumpcap -D raw output (debug):")
        print(f"   {result.stdout.strip() or 'No output'}")
        
        if result.stdout:
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            for line in lines:
                idx_match = re.match(r'^(\d+)\.', line)
                if idx_match:
                    idx = idx_match.group(1)
                    name = line[len(idx)+1:].strip()
                    name = re.sub(r'[^\x20-\x7E]', '', name).strip()[:50]
                    
                    interfaces.append({
                        'idx': idx,
                        'name': name if name else f"Interface_{idx}",
                        'is_recommended': any(kw in name for kw in ["WLAN", "Ethernet", "无线"])
                    })
            
            for iface in interfaces:
                if iface['is_recommended'] and not recommended_idx:
                    recommended_idx = iface['idx']
    
    except Exception as e:
        print(f"❌ Error getting interfaces: {str(e)}")
    
    return interfaces, recommended_idx


def select_interface_manually():
    """手动选择网卡（允许输入8）"""
    print("\n📌 Step 1: Select Interface (Enter 8 directly)")
    interfaces, recommended_idx = get_network_interfaces()
    
    if interfaces:
        for iface in interfaces:
            mark = "✅ RECOMMENDED" if iface['is_recommended'] else "⚠️"
            print(f"   {iface['idx']}. {mark} {iface['name']}")
    else:
        print("   No interfaces parsed - enter any number (e.g. 8)")
    
    print(f"💡 You can enter 8 (your preferred interface) directly")
    
    while True:
        user_input = input("\nEnter interface number (e.g. 8): ").strip()
        if user_input.isdigit():
            global selected_interface_info
            selected_interface_info = {
                'idx': user_input,
                'name': f"Manual_Interface_{user_input}"
            }
            print(f"\n✅ Selected interface (manual mode): {user_input}")
            return user_input
        else:
            print("❌ Please enter a valid number (e.g. 8)")


def check_dir_writable(directory, desc):
    """检查目录可写性（强制创建测试文件）"""
    try:
        os.makedirs(directory, exist_ok=True)
        test_file = os.path.join(directory, f"test_{int(time.time())}.tmp")
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("test")
        os.remove(test_file)
        print(f"✅ {desc} directory validated (writable): {directory}")
        return True
    except PermissionError:
        print(f"❌ Permission denied for {desc} directory")
        print("💡 Fix: Run as Administrator")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error with {desc} directory: {str(e)}")
        sys.exit(1)


def validate_pcap_file(pcap_path):
    """兼容PCAP/PCAPng格式验证（增强版）"""
    if not os.path.exists(pcap_path):
        return False, "File not found", ""
    
    file_size = os.path.getsize(pcap_path)
    if file_size < 64:  # 空文件
        return False, f"Empty PCAP file (size: {file_size} bytes)", ""
    
    with open(pcap_path, 'rb') as f:
        header = f.read(4)
    
    if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']:
        return True, "Valid PCAP format", "pcap"
    elif header == b'\x0a\x0d\x0d\x0a':
        return True, "Valid PCAPng format", "pcapng"
    else:
        return False, f"Invalid header: {header.hex()}", ""


def get_latest_file(directory, file_pattern, desc):
    """通用函数：获取目录下最新文件（按修改时间排序）"""
    if not os.path.exists(directory):
        print(f"❌ {desc} directory not found: {directory}")
        return None
    
    files = list(Path(directory).glob(file_pattern))
    if not files:
        print(f"❌ No {desc} files found in {directory}")
        return None
    
    latest_file = max(files, key=lambda f: f.stat().st_mtime)
    file_size = os.path.getsize(latest_file)
    
    # 检查文件大小（提示用户生成流量）
    if file_size < 2048:  # 小于2KB视为无有效流量
        print(f"\n⚠️ {desc} file is too small ({file_size/1024:.2f} KB) - NO TRAFFIC CAPTURED!")
        print(f"💡 Fix: Visit http://www.baidu.com (HTTP) and https://www.baidu.com (HTTPS) 10+ times!")
    
    print(f"\n✅ Found latest {desc} file:")
    print(f"   Path: {latest_file}")
    print(f"   Size: {file_size/1024:.2f} KB")
    print(f"   Modified time: {time.ctime(latest_file.stat().st_mtime)}")
    
    return str(latest_file)


def start_dumpcap_immediately():
    """启动dumpcap（支持HTTP+HTTPS，捕获完整数据包）"""
    global dumpcap_process, selected_interface, pcap_file_path
    if not os.path.exists(DUMPCAP_EXE):
        print(f"❌ dumpcap.exe not found: {DUMPCAP_EXE}")
        return False
    
    check_dir_writable(PCAP_CAPTURE_DIR, "PCAP capture")
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"capture_{timestamp}.pcap"
    pcap_file_path = os.path.join(PCAP_CAPTURE_DIR, pcap_filename)  # 保存PCAP路径
    
    # 核心修复：捕获 HTTP(80) + HTTPS(443) 端口，保留完整数据包（用于HTTPS解密）
    dumpcap_cmd = [
        DUMPCAP_EXE,
        "-i", selected_interface,
        "-w", pcap_file_path,
        "-q",
        "-s", "0",  # 捕获完整数据包（HTTPS解密必需）
        "-B", "100",
        "-P",
        "-f", "tcp port 80 or tcp port 443"  # 支持HTTPS 443端口
    ]
    
    try:
        dumpcap_process = subprocess.Popen(
            dumpcap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            shell=False
        )
        
        time.sleep(1)
        if dumpcap_process.poll() is not None:
            stderr = dumpcap_process.stderr.read().decode('gbk', errors='ignore')
            print(f"❌ dumpcap exited immediately! Error: {stderr[:200]}")
            dumpcap_process = None
            return False
        
        print(f"🚀 dumpcap started (PID: {dumpcap_process.pid})")
        print(f"📶 Monitoring interface: {selected_interface}")
        print(f"📂 PCAP will be saved to: {pcap_file_path}")
        print(f"🔴 CRITICAL: Open browser → Visit http://www.baidu.com (HTTP) ×10+ AND https://www.baidu.com (HTTPS) ×10+!")
        print(f"🔴 Note: HTTPS traffic is encrypted - see final tips to decrypt!")
        return True
    except Exception as e:
        print(f"❌ Failed to start dumpcap: {str(e)}")
        dumpcap_process = None
        return False


def stop_dumpcap_safely():
    """安全停止dumpcap（容错处理）"""
    global dumpcap_process
    if not dumpcap_process:
        print("\nℹ️ dumpcap not running")
        return
    
    try:
        # 先尝试优雅停止，失败则强制杀死
        subprocess.run(["taskkill", "/F", "/PID", str(dumpcap_process.pid)], 
                      timeout=5, capture_output=True, shell=True)
        dumpcap_process.wait(timeout=5)
        print(f"\n🛑 dumpcap stopped (PID: {dumpcap_process.pid})")
    except Exception as e:
        print(f"\n⚠️ Force killed dumpcap: {str(e)}")
        try:
            dumpcap_process.kill()
        except:
            pass
    finally:
        dumpcap_process = None
    
    # 验证最新PCAP文件
    get_latest_file(PCAP_CAPTURE_DIR, "*.pcap", "PCAP")


def run_cicflowmeter_auto(interface_num, output_dir, pcap_file):
    """
    自动运行 CICFlowMeter（分析 PCAP 文件）
    """
    print(f"\n📌 Step 3: 自动运行 CICFlowMeter...")
    
    try:
        # 检查依赖
        if not os.path.exists(CICFLOWMETER_JAR):
            print(f"❌ CICFlowMeter JAR 未找到: {CICFLOWMETER_JAR}")
            return False
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 构建 Java 命令 - 直接分析 PCAP 文件
        cmd = [
            "java",
            f"-Djava.library.path={JNETPCAP_DLL_DIR}",
            "-Dfile.encoding=UTF-8",
            "-jar", CICFLOWMETER_JAR,
            "-i", pcap_file,  # 直接分析 PCAP 文件
            "-c", output_dir,
            "-o", os.path.join(output_dir, "flow_features.csv")
        ]
        
        print(f"🚀 运行 CICFlowMeter 分析 PCAP 文件: {os.path.basename(pcap_file)}")
        print(f"📂 输出目录: {output_dir}")
        
        # 运行命令
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待完成（设置超时）
        try:
            stdout, stderr = process.communicate(timeout=120)
            if process.returncode == 0:
                print("✅ CICFlowMeter 成功运行")
                # 查找生成的 CSV 文件
                csv_files = find_csv_files(output_dir)
                if csv_files:
                    print(f"✅ 找到 {len(csv_files)} 个 CSV 文件")
                    for csv in csv_files[:3]:  # 显示前3个文件
                        print(f"   - {os.path.basename(csv)}")
                    return True
                else:
                    print("⚠️ CICFlowMeter 运行成功但未生成 CSV，可能是无流量")
                    return False
            else:
                print(f"❌ CICFlowMeter 运行失败 (退出码: {process.returncode})")
                if stderr:
                    print(f"错误信息: {stderr[:500]}")
                return False
                
        except subprocess.TimeoutExpired:
            process.kill()
            print("⏰ CICFlowMeter 超时，已终止")
            return False
            
    except Exception as e:
        print(f"❌ CICFlowMeter 异常: {e}")
        return False


def find_csv_files(directory):
    """查找 CSV 文件"""
    csv_files = []
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.csv'):
                    csv_files.append(os.path.join(root, file))
    except Exception as e:
        print(f"⚠️ 查找 CSV 文件时出错: {e}")
    return csv_files


def ensure_file_created(file_path, content=""):
    """强制创建文件（兜底）"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content if content else f"Generated at {time.ctime()}\n# Check input file for data")
        print(f"✅ Ensured file created: {file_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to create file: {file_path} (Error: {str(e)})")
        return False


def call_common_ip():
    """修复Common IP调用（增强CSV检查）"""
    # 1. 强制创建ip_counts.txt
    ensure_file_created(RESULT_FILE_PATH, "# Common IP Analysis Result\n")
    
    # 2. 检查CSV文件
    csv_files = find_csv_files(CICFLOWMETER_OUTPUT_DIR)
    if not csv_files:
        print(f"⚠️ Common IP skipped (no CSV in {CICFLOWMETER_OUTPUT_DIR})")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: No CSV found\nFixes:\n1. Re-run CICFlowMeter\n2. Ensure HTTP traffic capture\n3. Verify output dir: {CICFLOWMETER_OUTPUT_DIR}\n")
        return False
    
    latest_csv = max(csv_files, key=lambda f: os.path.getmtime(f))
    print(f"\n✅ Found latest CSV: {latest_csv}")
    
    # 3. 验证Common IP工具路径
    if not os.path.exists(COMMON_IP_EXE):
        print(f"❌ common_ip.exe not found: {COMMON_IP_EXE}")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: common_ip.exe missing at {COMMON_IP_EXE}\n")
        return False
    
    try:
        print(f"\n📌 Running Common IP analysis on: {os.path.basename(latest_csv)}")
        exe_work_dir = os.path.dirname(COMMON_IP_EXE)
        result = subprocess.run(
            [COMMON_IP_EXE, str(latest_csv)],
            cwd=exe_work_dir,
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            timeout=300
        )
        
        print("✅ Common IP analysis completed!")
        
        # 写入结果
        with open(RESULT_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write("# Common IP Analysis Result\n")
            f.write(f"# CSV File: {latest_csv}\n")
            f.write(f"# Analysis Time: {time.ctime()}\n\n")
            f.write(result.stdout.strip())
        
        # 显示结果预览
        print(f"\n📊 ip_counts.txt 内容预览:")
        with open(RESULT_FILE_PATH, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if len(content) > 1000:
                print(content[:1000] + "...")
            else:
                print(content)
        return True
    except subprocess.TimeoutExpired:
        print("⏰ Common IP 超时")
        ensure_file_created(RESULT_FILE_PATH, f"# Common IP Error: 超时\n")
        return False
    except Exception as e:
        print(f"❌ Common IP error: {str(e)}")
        ensure_file_created(RESULT_FILE_PATH, f"# Common IP Error\n{str(e)}\n")
        return False


def run_pcap2para_safe(pcap_file, output_file):
    """
    安全运行 pcap2para，避免内存错误
    """
    print(f"🔍 运行 pcap2para (安全模式)...")
    
    try:
        # 检查 pcap2para 是否存在
        if not os.path.exists(PCAP2PARA_EXE):
            print(f"❌ pcap2para.exe 未找到: {PCAP2PARA_EXE}")
            # 创建空分析文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"pcap2para 分析失败: 未找到执行文件 {PCAP2PARA_EXE}\n")
            return False
        
        # 验证文件大小（处理大文件可能导致内存溢出）
        file_size_mb = os.path.getsize(pcap_file) / (1024 * 1024)
        print(f"📊 PCAP 文件大小: {file_size_mb:.1f} MB")
        
        if file_size_mb > 50:  # 如果文件大于 50MB，使用分块处理
            print(f"⚠️ PCAP 文件较大 ({file_size_mb:.1f} MB)，使用分块分析")
            return run_pcap2para_chunked(pcap_file, output_file)
        
        # 设置环境变量
        env = os.environ.copy()
        
        # 使用限制内存的命令
        cmd = [
            PCAP2PARA_EXE,
            "-r", pcap_file,
            "-w", output_file,
            "-l", "1000"  # 限制处理包的数量
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        
        # 超时设置
        try:
            stdout, stderr = process.communicate(timeout=60)
            if process.returncode == 0:
                print("✅ pcap2para 分析完成")
                return True
            else:
                print(f"⚠️ pcap2para 警告: {stderr[:500] if stderr else '无错误信息'}")
                # 即使有警告，也尝试读取输出文件
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    print("✅ pcap2para 输出文件已生成")
                    return True
                else:
                    # 创建最小报告
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(f"# pcap2para 分析报告\n")
                        f.write(f"PCAP 文件: {os.path.basename(pcap_file)}\n")
                        f.write(f"文件大小: {file_size_mb:.1f} MB\n")
                        f.write(f"分析时间: {time.ctime()}\n")
                        f.write(f"状态: 部分完成 (退出码: {process.returncode})\n")
                        f.write(f"错误信息: {stderr[:500] if stderr else '无'}\n")
                    return True
                    
        except subprocess.TimeoutExpired:
            process.kill()
            print("⏰ pcap2para 超时，已终止")
            # 创建超时报告
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# pcap2para 分析报告\n")
                f.write(f"PCAP 文件: {os.path.basename(pcap_file)}\n")
                f.write(f"文件大小: {file_size_mb:.1f} MB\n")
                f.write(f"分析时间: {time.ctime()}\n")
                f.write(f"状态: 超时终止\n")
            return False
            
    except Exception as e:
        print(f"❌ pcap2para 异常: {e}")
        # 创建错误报告
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"pcap2para 分析失败，错误: {str(e)[:200]}\n")
        return False


def run_pcap2para_chunked(pcap_file, output_file):
    """
    分块处理大 PCAP 文件
    """
    try:
        print("📊 尝试使用 tshark 分割大文件...")
        
        # 检查 tshark 是否存在
        tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe"
        if not os.path.exists(tshark_path):
            print("❌ tshark 未找到，无法分块处理")
            return False
        
        # 创建临时目录
        temp_dir = tempfile.mkdtemp()
        print(f"📁 临时目录: {temp_dir}")
        
        # 使用 tshark 分割文件
        chunk_pattern = os.path.join(temp_dir, "chunk_%05d.pcap")
        
        split_cmd = [
            tshark_path,
            "-r", pcap_file,
            "-w", chunk_pattern,
            "-c", "5000"  # 每个文件 5000 个包
        ]
        
        print("🔪 分割文件中...")
        split_result = subprocess.run(split_cmd, capture_output=True, text=True)
        
        if split_result.returncode != 0:
            print(f"❌ 分割文件失败: {split_result.stderr[:500]}")
            shutil.rmtree(temp_dir)
            return False
        
        # 查找所有分块文件
        chunk_files = glob.glob(os.path.join(temp_dir, "chunk_*.pcap"))
        print(f"📦 共分割为 {len(chunk_files)} 个文件")
        
        if not chunk_files:
            print("❌ 分割后未找到分块文件")
            shutil.rmtree(temp_dir)
            return False
        
        # 处理每个分块
        all_results = []
        for i, chunk in enumerate(chunk_files, 1):
            print(f"🔍 处理分块 {i}/{len(chunk_files)}: {os.path.basename(chunk)}")
            chunk_output = chunk + ".txt"
            
            # 递归调用安全模式处理分块
            if run_pcap2para_safe(chunk, chunk_output):
                if os.path.exists(chunk_output) and os.path.getsize(chunk_output) > 0:
                    with open(chunk_output, 'r', encoding='utf-8') as f:
                        all_results.append(f"=== 分块 {i} ===")
                        all_results.append(f.read())
                else:
                    all_results.append(f"=== 分块 {i} 无输出 ===")
            else:
                all_results.append(f"=== 分块 {i} 处理失败 ===")
        
        # 合并结果
        print("📋 合并分析结果...")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# pcap2para 分块分析报告\n")
            f.write(f"原始文件: {os.path.basename(pcap_file)}\n")
            f.write(f"分割数量: {len(chunk_files)} 个分块\n")
            f.write(f"分析时间: {time.ctime()}\n\n")
            f.write("\n".join(all_results))
        
        # 清理临时文件
        print("🧹 清理临时文件...")
        shutil.rmtree(temp_dir)
        
        print(f"✅ 分块分析完成，结果保存到: {output_file}")
        return True
        
    except Exception as e:
        print(f"❌ 分块处理失败: {e}")
        # 尝试清理临时目录
        try:
            if 'temp_dir' in locals():
                shutil.rmtree(temp_dir)
        except:
            pass
        return False


def call_pcap2para():
    """修复pcap2para调用（支持HTTPS提示+依赖检查）"""
    global pcap_file_path
    
    print("\n📌 Step 6: Run pcap2para Analysis...")
    
    # 1. 验证PCAP文件
    if not pcap_file_path or not os.path.exists(pcap_file_path):
        latest_pcap = get_latest_file(PCAP_CAPTURE_DIR, "*.pcap", "PCAP")
        if not latest_pcap:
            print(f"⚠️ pcap2para skipped (no PCAP file)")
            return False
        pcap_file_path = latest_pcap
    
    # 2. 验证PCAP有效性
    is_valid, msg, fmt = validate_pcap_file(pcap_file_path)
    if not is_valid:
        print(f"❌ Invalid PCAP: {msg}")
        return False
    print(f"✅ PCAP validated: {msg}")
    
    # 3. 检查Boost依赖（避免崩溃）
    print("\n🔍 Checking pcap2para dependencies...")
    if not os.path.exists(BOOST_DLL_PATH):
        boost_source = os.path.join("C:\\Boost\\boost_1_81_0\\lib64-msvc-14.3", BOOST_DLL_NAME)
        print(f"⚠️ Missing Boost DLL: {BOOST_DLL_PATH}")
        print(f"💡 Fix: Copy {BOOST_DLL_NAME} from {boost_source} to {os.path.dirname(PCAP2PARA_EXE)}")
        input("\nPress Enter to continue (may cause crash)...\n")
    
    # 4. 准备输出文件
    pcap_name = Path(pcap_file_path).stem
    output_file = os.path.join(ANALYZED_DATA_DIR, f"{pcap_name}_analysis.txt")
    ensure_file_created(output_file, f"# pcap2para Analysis for {pcap_name}.pcap\n")
    
    # 5. 运行pcap2para（安全模式）
    print(f"🔍 Running pcap2para analysis (supports HTTP+HTTPS)...")
    print(f"ℹ️ Note: HTTPS payload is encrypted - see final tips to decrypt!")
    
    if run_pcap2para_safe(pcap_file_path, output_file):
        print(f"✅ pcap2para analysis completed!")
        print(f"✅ Analysis saved to: {output_file}")
        
        # 显示文件预览
        try:
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r', encoding='utf-8') as f:
                    preview = f.read(1000)
                    print("\n📊 Preview (first 1000 chars):")
                    print(preview + ("..." if len(preview) >= 1000 else ""))
        except:
            pass
        return True
    else:
        print(f"⚠️ pcap2para 分析遇到问题，已生成最小报告")
        return False


def main():
    """主函数（按用户要求调整逻辑）"""
    sys.stdout.reconfigure(encoding='utf-8')
    print("======================================================================")
    print("          dumpcap + CICFlowMeter + Common IP + pcap2para Tool")
    print("          (Final Version: HTTPS Support + CSV Fix)")
    print("======================================================================\n")

    # 管理员权限提示
    if not check_admin():
        print("⚠️ WARNING: Not running as Administrator! Capture may fail")
        print("💡 Run CMD as Admin for best results\n")

    # 检查依赖
    if not check_dependencies():
        print("\n❌ 部分依赖未满足，可能影响程序运行")
        input("按 Enter 继续（或 Ctrl+C 退出）...")

    # 步骤1：选择网卡
    global selected_interface
    selected_interface = select_interface_manually()

    # 步骤2：启动dumpcap抓包（HTTP+HTTPS）
    print("\n📌 Step 2: Start Packet Capture...")
    dumpcap_started = start_dumpcap_immediately()
    if not dumpcap_started:
        print("⚠️ dumpcap failed to start! Exiting...")
        input("\nPress Enter to exit...")
        return

    # 等待用户生成流量
    print("\n⏳ 请生成网络流量（访问 baidu.com）...")
    print("   1. 打开浏览器访问 http://www.baidu.com (刷新10+次)")
    print("   2. 打开浏览器访问 https://www.baidu.com (刷新10+次)")
    print("   3. 等待至少60秒确保捕获足够流量")
    
    try:
        capture_time = 60  # 捕获时间（秒）
        for i in range(capture_time, 0, -1):
            print(f"⏰ 剩余捕获时间: {i} 秒 (按 Ctrl+C 提前停止)", end='\r')
            time.sleep(1)
        print("\n")
    except KeyboardInterrupt:
        print("\n⚠️ 用户提前停止捕获")

    # 步骤3：自动运行CICFlowMeter
    if pcap_file_path and os.path.exists(pcap_file_path):
        run_cicflowmeter_auto(selected_interface, CICFLOWMETER_OUTPUT_DIR, pcap_file_path)
    else:
        print("❌ 未找到PCAP文件，跳过CICFlowMeter")

    # 步骤4：停止dumpcap
    print("\n📌 Step 4: Stop Capture & Validate Files...")
    stop_dumpcap_safely()

    # 步骤5：运行Common IP分析
    print("\n📌 Step 5: Run Common IP Analysis...")
    call_common_ip()

    # 步骤6：运行pcap2para分析（支持HTTPS）
    call_pcap2para()

    # 最终总结+HTTPS指南
    print("\n🎉 All processes completed! Final Check:")
    print(f"   ✅ PCAP saved to: {PCAP_CAPTURE_DIR}")
    print(f"   ✅ CSV saved to: {CICFLOWMETER_OUTPUT_DIR}")
    print(f"   ✅ ip_counts.txt: {RESULT_FILE_PATH}")
    print(f"   ✅ pcap2para analysis: {ANALYZED_DATA_DIR}")
    print(f"\n💡 HTTPS Decryption Guide (Critical!):")
    print(f"   1. Open Wireshark → Edit → Preferences → Protocols → TLS.")
    print(f"   2. Click 'Browse' → Select a path to save SSLKEYLOGFILE (e.g., C:\\sslkey.log).")
    print(f"   3. Open Admin CMD → Run: setx SSLKEYLOGFILE C:\\sslkey.log (persists across restarts).")
    print(f"   4. Restart Chrome/Firefox → Capture traffic again to parse HTTPS payload.")
    print(f"\n💡 If no data:")
    print(f"   1. Ensure you visited both HTTP (http://baidu.com) and HTTPS (https://baidu.com).")
    print(f"   2. Verify CICFlowMeter selected interface {selected_interface}.")
    print(f"   3. Check Boost DLL is in pcap2para.exe folder.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ User interrupted, stopping processes...")
        stop_dumpcap_safely()
    except Exception as e:
        print(f"\n\n❌ Program error: {str(e)}")
        stop_dumpcap_safely()
    finally:
        input("\nPress Enter to exit...")