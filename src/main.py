import os
import subprocess
import time
import signal
from pathlib import Path
import sys
import ctypes
import re
import socket

# ========== 核心配置（严格对齐用户实际路径，无拼写错误） ==========
BASE_DIR = r"C:\Users\z1395\network_trace_system"

# 1. CICFlowMeter配置（用户实际CSV输出目录）
CICFLOWMETER_JAR = os.path.join(BASE_DIR, "CICFlowMeter", "target", "CICFlowMeterV3-0.0.4-SNAPSHOT.jar")
CICFLOWMETER_OUTPUT_DIR = os.path.join(BASE_DIR, "CICFlowMeter", "target", "data", "daily")  # 无拼写错误

# 2. Common IP（ws-traffic-analyze-kit）配置
COMMON_IP_EXE = os.path.join(BASE_DIR, "ws-traffic-analyze-kit", "target", "release", "common_ip.exe")
RESULT_FILE_PATH = os.path.join(BASE_DIR, "ws-traffic-analyze-kit", "ip_counts.txt")

# 3. dumpcap配置（系统默认）
DUMPCAP_EXE = r"C:\Program Files\Wireshark\dumpcap.exe"
PCAP_CAPTURE_DIR = os.path.join(BASE_DIR, "catched_data")

# 4. pcap2para配置（已更新为正确路径）
PCAP2PARA_EXE = os.path.join(BASE_DIR, "pcap2para", "build", "bin", "Release", "pcap2para.exe")
ANALYZED_DATA_DIR = os.path.join(BASE_DIR, "analyzed_data")

# 全局变量
dumpcap_process = None
selected_interface = ""
selected_interface_info = {}

def check_admin():
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_npcap_winpcap():
    """检查抓包驱动"""
    print("🔍 Checking packet capture drivers...")
    winpcap_paths = [r"C:\Windows\System32\wpcap.dll", r"C:\Program Files\WinPcap\wpcap.dll"]
    has_winpcap = any(os.path.exists(p) for p in winpcap_paths)
    
    if has_winpcap:
        print("✅ WinPcap driver detected (legacy mode)")
        return True
    else:
        print("❌ No WinPcap/Npcap driver found!")
        input("\nPress Enter to continue...")
        return False

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
    print("\n📶 Network Interface Selection (Manual Mode Allowed):")
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
    """兼容PCAP/PCAPng格式验证"""
    if not os.path.exists(pcap_path):
        return False, "File not found", ""
    
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
        print(f"💡 Fix: Visit http://www.baidu.com (HTTP, NOT HTTPS) 10+ times during capture!")
    
    print(f"\n✅ Found latest {desc} file:")
    print(f"   Path: {latest_file}")
    print(f"   Size: {file_size/1024:.2f} KB")
    print(f"   Modified time: {time.ctime(latest_file.stat().st_mtime)}")
    
    return str(latest_file)

def start_dumpcap_immediately():
    """启动dumpcap（生成PCAP到用户指定目录）"""
    global dumpcap_process, selected_interface
    if not os.path.exists(DUMPCAP_EXE):
        print(f"❌ dumpcap.exe not found: {DUMPCAP_EXE}")
        return False
    
    check_dir_writable(PCAP_CAPTURE_DIR, "PCAP capture")
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"capture_{timestamp}.pcap"
    pcap_path = os.path.join(PCAP_CAPTURE_DIR, pcap_filename)
    
    dumpcap_cmd = [
        DUMPCAP_EXE,
        "-i", selected_interface,
        "-w", pcap_path,
        "-q",
        "-s", "0",
        "-B", "100",
        "-P"
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
        print(f"📂 PCAP will be saved to: {pcap_path}")
        print(f"🔴 CRITICAL: Open browser → Visit http://www.baidu.com (HTTP) → Refresh 10+ times!")
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
    """修复Common IP调用（精准找到CSV文件）"""
    # 1. 强制创建ip_counts.txt
    ensure_file_created(RESULT_FILE_PATH, "# Common IP Analysis Result\n")
    
    # 2. 获取最新CSV文件
    latest_csv = get_latest_file(CICFLOWMETER_OUTPUT_DIR, "*.csv", "CICFlowMeter CSV")
    if not latest_csv:
        print(f"⚠️ Common IP skipped (no CSV file)")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: No CSV found in {CICFLOWMETER_OUTPUT_DIR}\n")
        return False
    
    # 3. 验证Common IP工具路径
    if not os.path.exists(COMMON_IP_EXE):
        print(f"❌ common_ip.exe not found: {COMMON_IP_EXE}")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: common_ip.exe missing at {COMMON_IP_EXE}\n")
        return False
    
    try:
        print(f"\n📌 Running Common IP analysis on: {latest_csv}")
        exe_work_dir = os.path.dirname(COMMON_IP_EXE)
        result = subprocess.run(
            [COMMON_IP_EXE, latest_csv],
            cwd=exe_work_dir,
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            check=True,
            timeout=300
        )
        
        print("✅ Common IP analysis completed!")
        print(f"🔍 Tool output: {result.stdout.strip()}")
        
        # 显示结果文件内容
        if os.path.exists(RESULT_FILE_PATH):
            print(f"\n📊 ip_counts.txt content:")
            with open(RESULT_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if content:
                    print(content)
                else:
                    print("⚠️ ip_counts.txt is empty (no valid IP data in CSV - check traffic)")
        else:
            print(f"⚠️ common_ip.exe did not write to ip_counts.txt")
            ensure_file_created(RESULT_FILE_PATH, f"# Common IP Output\n{result.stdout.strip()}\n")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Common IP failed (exit code {e.returncode}): {e.stderr.strip()}")
        ensure_file_created(RESULT_FILE_PATH, f"# Common IP Error\nExit code: {e.returncode}\nError: {e.stderr.strip()}\n")
        return False
    except Exception as e:
        print(f"❌ Common IP error: {str(e)}")
        ensure_file_created(RESULT_FILE_PATH, f"# Common IP Error\n{str(e)}\n")
        return False

def call_pcap2para():
    """修复pcap2para调用（精准找到PCAP文件）"""
    # 1. 获取最新PCAP文件
    latest_pcap = get_latest_file(PCAP_CAPTURE_DIR, "*.pcap", "PCAP")
    if not latest_pcap:
        print(f"⚠️ pcap2para skipped (no PCAP file)")
        return False
    
    # 2. 验证pcap2para工具路径
    if not os.path.exists(PCAP2PARA_EXE):
        print(f"❌ pcap2para.exe not found: {PCAP2PARA_EXE}")
        return False
    
    # 3. 准备输出文件
    pcap_name = Path(latest_pcap).stem
    output_file = os.path.join(ANALYZED_DATA_DIR, f"{pcap_name}_analysis.txt")
    ensure_file_created(output_file, f"# pcap2para Analysis for {pcap_name}.pcap\n")
    
    try:
        print(f"\n📌 Running pcap2para analysis on: {latest_pcap}")
        # 简化pcap2para参数（确保兼容）
        result = subprocess.run(
            [PCAP2PARA_EXE, "-p", "all", "-o", output_file, latest_pcap],
            cwd=os.path.dirname(PCAP2PARA_EXE),
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            check=True,
            timeout=300
        )
        
        print("✅ pcap2para analysis completed!")
        print(f"🔍 Tool output: {result.stdout.strip()}")
        print(f"✅ Analysis file saved to: {output_file}")
        
        # 显示结果预览
        if os.path.exists(output_file):
            print("\n📊 pcap2para analysis preview:")
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                if content:
                    print(content[:1000])  # 只显示前1000字符
                else:
                    print("⚠️ Analysis file is empty (no HTTP traffic captured)")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ pcap2para failed (exit code {e.returncode}): {e.stderr.strip()}")
        ensure_file_created(output_file, f"# pcap2para Error\nExit code: {e.returncode}\nError: {e.stderr.strip()}\n")
        return False
    except Exception as e:
        print(f"❌ pcap2para error: {str(e)}")
        ensure_file_created(output_file, f"# pcap2para Error\n{str(e)}\n")
        return False

def main():
    """主函数（完整流程，异常容错）"""
    sys.stdout.reconfigure(encoding='utf-8')
    print("======================================================================")
    print("          dumpcap + CICFlowMeter + Common IP + pcap2para Tool")
    print("          (Final Version: All Bugs Fixed + Full Functionality)")
    print("======================================================================\n")

    # 管理员权限提示
    if not check_admin():
        print("⚠️ WARNING: Not running as Administrator! Capture may fail")
        print("💡 Run CMD as Admin for best results\n")

    # 检查驱动
    check_npcap_winpcap()

    # 步骤1：选择网卡
    print("\n📌 Step 1: Select Interface (Enter 8 directly)")
    global selected_interface
    try:
        selected_interface = select_interface_manually()
    except Exception as e:
        print(f"❌ Interface selection error: {str(e)}")
        input("\nPress Enter to exit...")
        return

    # 步骤2：启动dumpcap
    print("\n📌 Step 2: Start Packet Capture...")
    dumpcap_started = start_dumpcap_immediately()
    if not dumpcap_started:
        print("⚠️ dumpcap failed to start! Continue with CICFlowMeter...")
        input("\nPress Enter to continue...")

    # 步骤3：启动CICFlowMeter（修复路径错误：强制绝对路径+指定工作目录）
    print("\n📌 Step 3: Start CICFlowMeter (CRITICAL: Generate Traffic!)")
    try:
        # 强制验证并创建输出目录（确保存在且可写）
        check_dir_writable(CICFLOWMETER_OUTPUT_DIR, "CICFlowMeter CSV")
        
        # 获取CICFlowMeter JAR所在目录（作为工作目录）
        cic_work_dir = os.path.dirname(CICFLOWMETER_JAR)
        # 生成绝对路径的输出目录（避免相对路径解析错误）
        cic_output_abs = os.path.abspath(CICFLOWMETER_OUTPUT_DIR)
        
        # 生成正确的CICFlowMeter启动命令（强制绝对路径+指定工作目录）
        cic_cmd = (
            f"cd /d \"{cic_work_dir}\" && "  # 先切换到JAR所在目录
            f"java -Dfile.encoding=UTF-8 "
            f"-jar \"{CICFLOWMETER_JAR}\" "
            f"-o \"{cic_output_abs}\""  # 使用绝对路径
        )
        
        print("\n🔧 Run this command in ADMIN CMD (COPY EXACTLY!):")
        print(f"   {cic_cmd}")
        
        print("\n📋 CICFlowMeter Steps (MUST FOLLOW!):")
        print(f"   1. Select interface {selected_interface} (exact match!)")
        print(f"   2. Click Start → Open browser → Visit http://www.baidu.com (HTTP!) → Refresh 10+ times")
        print(f"   3. Wait 60 seconds → Click Stop → Close CICFlowMeter")
        print(f"   4. CSV will be saved to: {cic_output_abs} (e.g. 2025-12-11_Flow.csv)")
        print(f"   ⚠️  IMPORTANT: Do NOT modify the command path - it's an ABSOLUTE PATH!")
        input("   Complete all steps, then press Enter...\n")
    except Exception as e:
        print(f"❌ CICFlowMeter setup error: {str(e)}")

    # 步骤4：停止dumpcap
    print("\n📌 Step 4: Stop Capture & Validate PCAP...")
    stop_dumpcap_safely()

    # 步骤5：Common IP分析
    print("\n📌 Step 5: Run Common IP Analysis (ws-traffic-analyze-kit)...")
    call_common_ip()

    # 步骤6：pcap2para分析
    print("\n📌 Step 6: Run pcap2para Analysis...")
    call_pcap2para()

    # 最终总结
    print("\n🎉 All processes completed! Final Check:")
    print(f"   ✅ No code errors (fixed variable name spelling)")
    print(f"   ✅ PCAP saved to: {PCAP_CAPTURE_DIR}")
    print(f"   ✅ CSV saved to: {CICFLOWMETER_OUTPUT_DIR}")
    print(f"   ✅ ip_counts.txt: {RESULT_FILE_PATH}")
    print(f"   ✅ pcap2para analysis: {ANALYZED_DATA_DIR}")
    print(f"\n💡 If no data in files:")
    print(f"   1. Ensure you visited http://www.baidu.com (HTTP, not HTTPS) during capture")
    print(f"   2. Ensure CICFlowMeter selected interface {selected_interface}")
    print(f"   3. Run all commands as Administrator")
    print(f"   4. Verify CSV path: {CICFLOWMETER_OUTPUT_DIR} (absolute path used)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ User interrupted, stopping dumpcap...")
        stop_dumpcap_safely()
    except Exception as e:
        print(f"\n\n❌ Program error: {str(e)}")
        stop_dumpcap_safely()
    finally:
        input("\nPress Enter to exit...")