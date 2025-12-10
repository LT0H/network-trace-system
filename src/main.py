import os
import subprocess
import time
import signal
from pathlib import Path
import sys
import ctypes
import re

# ========== 核心路径配置（全绝对路径，确保可写） ==========
# CICFlowMeter 相关
CICFLOWMETER_JAR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
CICFLOWMETER_OUTPUT_DIR = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\data\daily"
CICFLOWMETER_FALLBACK_DIR = r"C:\Windows\System32\data\daily"

# 枫叶分析工具相关
COMMON_IP_EXE = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\target\release\common_ip.exe"
RESULT_FILE_PATH = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\ip_counts.txt"

# ========== dumpcap + pcap2para 配置 ==========
DUMPCAP_EXE = r"C:\Program Files\Wireshark\dumpcap.exe"
PCAP_CAPTURE_DIR = r"C:\Users\z1395\network_trace_system\catched_data"
PCAP2PARA_EXE = r"C:\Users\z1395\network_trace_system\pcap2para\build\Release\pcap2para.exe"
ANALYZED_DATA_DIR = r"C:\Users\z1395\network_trace_system\analyzed_data"
DEFAULT_EXTRACT_PARAM = "rsa,ul,pl"

# 全局变量
dumpcap_process = None
dumpcap_base_pcap_name = ""
selected_interface = ""
selected_interface_info = {}  # 存储选中网卡的详细信息（英文名称/Device ID）

def check_admin():
    """检查是否以管理员身份运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_npcap_winpcap():
    """检查Npcap/WinPcap驱动（CICFlowMeter抓包必需）"""
    print("🔍 检查抓包驱动（CICFlowMeter必需）...")
    # 检查Npcap
    npcap_paths = [
        r"C:\Windows\System32\npcap.dll",
        r"C:\Program Files\Npcap\npcap.dll"
    ]
    # 检查WinPcap
    winpcap_paths = [
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Program Files\WinPcap\wpcap.dll"
    ]
    
    has_npcap = any(os.path.exists(p) for p in npcap_paths)
    has_winpcap = any(os.path.exists(p) for p in winpcap_paths)
    
    if has_npcap:
        print("✅ 检测到Npcap驱动（推荐）")
        return True
    elif has_winpcap:
        print("✅ 检测到WinPcap驱动")
        return True
    else:
        print("❌ 未检测到Npcap/WinPcap驱动！CICFlowMeter无法抓包")
        print("💡 立即修复：下载安装Npcap（https://npcap.com/#download），勾选\"Install Npcap in WinPcap API-compatible Mode\"")
        input("\n安装完成后按Enter键继续...")
        return False

def get_network_interfaces():
    """获取网卡列表（纯英文展示，提取Device ID，解决乱码）"""
    if not os.path.exists(DUMPCAP_EXE):
        print(f"❌ Error: dumpcap.exe not found - {DUMPCAP_EXE}")
        print("💡 Solution: Install Wireshark (https://www.wireshark.org/)")
        sys.exit(1)
    
    try:
        # 直接获取原始输出（不做编码转换，避免乱码）
        result = subprocess.run(
            [DUMPCAP_EXE, "-D"],
            capture_output=True,
            encoding='utf-8',
            errors='replace'  # 替换无法解码的字符为?
        )
        
        interfaces = []
        recommended_idx = ""
        if result.stdout:
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            for line in lines:
                # 解析格式：1. \Device\NPF_{EB0F0C6E-FBB3-4BE0-A01C-B82E4EF1AC18} (WLAN)
                # 提取编号、Device ID、英文名称
                idx_match = re.match(r'^(\d+)\.', line)
                device_id_match = re.search(r'\\Device\\NPF_[0-9A-F-]+', line)
                name_match = re.search(r'\(([^)]+)\)', line)
                
                idx = idx_match.group(1) if idx_match else ""
                device_id = device_id_match.group(0) if device_id_match else ""
                en_name = name_match.group(1) if name_match else f"Interface_{idx}"
                
                # 清理名称（移除乱码字符）
                en_name = re.sub(r'[^\x20-\x7E]', '', en_name).strip()
                if not en_name:
                    en_name = f"Interface_{idx}"
                
                # 标记推荐网卡（WLAN/Ethernet/LAN）
                is_recommended = any(keyword in en_name for keyword in ["WLAN", "Ethernet", "LAN", "WiFi"])
                if is_recommended and not recommended_idx:
                    recommended_idx = idx
                
                interfaces.append({
                    'idx': idx,
                    'device_id': device_id,  # CICFlowMeter可识别的Device ID
                    'en_name': en_name,      # 纯英文名称
                    'full_line': line,       # 原始行
                    'is_recommended': is_recommended
                })
        return interfaces, recommended_idx
    except Exception as e:
        print(f"❌ Error getting network interfaces: {str(e)}")
        sys.exit(1)

def select_interface_manually():
    """手动选择网卡（展示英文名称+Device ID）"""
    print("📶 Available Network Interfaces (English Name / Device ID):")
    interfaces, recommended_idx = get_network_interfaces()
    if not interfaces:
        print("❌ No network interfaces detected!")
        sys.exit(1)
    
    # 展示网卡列表（纯英文）
    for iface in interfaces:
        mark = "*" if iface['is_recommended'] else " "
        print(f"   {iface['idx']}.{mark} {iface['en_name']}")
        print(f"      Device ID: {iface['device_id']}")
    
    # 提示推荐网卡
    if recommended_idx:
        recommended_iface = next(i for i in interfaces if i['idx'] == recommended_idx)
        print(f"\n💡 Recommended: {recommended_idx} ({recommended_iface['en_name']}) - Your active internet interface")
    
    # 输入验证
    valid_ids = [iface['idx'] for iface in interfaces]
    while True:
        user_input = input("\nEnter interface number to monitor (e.g. 6): ").strip()
        if user_input in valid_ids:
            selected_iface = next(iface for iface in interfaces if iface['idx'] == user_input)
            print(f"\n✅ Selected Interface:")
            print(f"   Number: {user_input}")
            print(f"   English Name: {selected_iface['en_name']}")
            print(f"   Device ID: {selected_iface['device_id']}")
            # 存储选中网卡信息
            global selected_interface_info
            selected_interface_info = selected_iface
            return user_input
        else:
            print(f"❌ Invalid input! Please select from: {','.join(valid_ids)}")

def check_dir_writable(directory, desc):
    """检查目录可写性"""
    try:
        os.makedirs(directory, exist_ok=True)
        test_file = os.path.join(directory, f"test_writable_{int(time.time())}.tmp")
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print(f"✅ {desc} directory validated (writable): {directory}")
        return True
    except PermissionError:
        print(f"❌ Error: {desc} directory not writable! Run as Administrator.")
        print(f"   Path: {directory}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error with {desc} directory: {str(e)}")
        sys.exit(1)

def get_latest_csv():
    """多目录查找CSV"""
    main_csv = _get_latest_csv_single_dir(CICFLOWMETER_OUTPUT_DIR)
    if main_csv:
        return main_csv
    fallback_csv = _get_latest_csv_single_dir(CICFLOWMETER_FALLBACK_DIR)
    if fallback_csv:
        print(f"⚠️ Warning: CSV file in system directory (permission issue): {fallback_csv}")
        return fallback_csv
    return None

def _get_latest_csv_single_dir(directory):
    """单个目录查找CSV"""
    if not os.path.exists(directory):
        return None
    csv_files = list(Path(directory).glob("*.csv"))
    if not csv_files:
        return None
    return max(csv_files, key=lambda f: f.stat().st_mtime)

def get_latest_pcap(directory, base_name=""):
    """查找最新有效PCAP"""
    check_dir_writable(directory, "Capture file")
    pcap_files = []
    if base_name:
        pcap_files = list(Path(directory).glob(f"{base_name}*.pcap")) + list(Path(directory).glob(f"{base_name}*.pcapng"))
    if not pcap_files:
        pcap_files = list(Path(directory).glob("*.pcap")) + list(Path(directory).glob("*.pcapng"))
    if not pcap_files:
        return None
    latest_pcap = max(pcap_files, key=lambda f: f.stat().st_mtime)
    if os.path.getsize(latest_pcap) < 1024:
        print(f"⚠️ Warning: Capture file too small: {latest_pcap} ({os.path.getsize(latest_pcap)} bytes)")
        return None
    return latest_pcap

def start_dumpcap_immediately():
    """启动dumpcap（使用英文网卡标识，确保和CICFlowMeter同步）"""
    global dumpcap_process, dumpcap_base_pcap_name, selected_interface
    if not os.path.exists(DUMPCAP_EXE):
        print(f"❌ Error: dumpcap.exe not found - {DUMPCAP_EXE}")
        return False
    
    # 创建抓包目录
    check_dir_writable(PCAP_CAPTURE_DIR, "Capture file")
    
    # 生成文件名
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    dumpcap_base_pcap_name = f"capture_{timestamp}"
    dumpcap_pcap_path = os.path.join(PCAP_CAPTURE_DIR, dumpcap_base_pcap_name + ".pcap")
    
    # 使用正确的dumpcap参数（无分片，避免文件分散）
    dumpcap_cmd = [
        DUMPCAP_EXE,
        "-i", selected_interface,          # 用户选择的网卡编号
        "-w", dumpcap_pcap_path,           # 输出文件
        "-q",                              # 安静模式
        "--time-stamp-type", "host"        # 时间戳同步
    ]
    
    try:
        # 启动dumpcap
        dumpcap_process = subprocess.Popen(
            dumpcap_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            shell=False
        )
        # 检查进程是否存活
        time.sleep(1)
        if dumpcap_process.poll() is not None:
            stderr = dumpcap_process.stderr.read().decode('utf-8', errors='ignore')
            print(f"❌ dumpcap exited immediately! Error: {stderr[:200]}...")
            print(f"💡 Solutions:")
            print(f"   1. Use recommended interface ({selected_interface_info.get('idx', '')} - {selected_interface_info.get('en_name', '')})")
            print(f"   2. Close firewall/antivirus (they block packet capture)")
            print(f"   3. Run CMD as Administrator")
            print(f"   4. Reinstall Npcap with WinPcap compatibility")
            dumpcap_process = None
            return False
        
        print(f"🚀 dumpcap started (PID: {dumpcap_process.pid})")
        print(f"📶 Monitoring interface: {selected_interface} ({selected_interface_info.get('en_name', '')})")
        print(f"📂 Capture file: {dumpcap_pcap_path}")
        print(f"💡 Critical: Visit HTTP website (http://www.baidu.com) during capture (not HTTPS!)")
        return True
    except Exception as e:
        print(f"❌ Failed to start dumpcap: {str(e)}")
        dumpcap_process = None
        return False

def stop_dumpcap_on_enter():
    """停止dumpcap"""
    global dumpcap_process, dumpcap_base_pcap_name
    if not dumpcap_process:
        print("\nℹ️ dumpcap not running or failed to start")
        return
    
    if dumpcap_process.poll() is not None:
        print(f"\nℹ️ dumpcap process already exited (PID: {dumpcap_process.pid})")
        dumpcap_process = None
        return
    
    # 终止进程
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(dumpcap_process.pid)], capture_output=True, timeout=5)
        dumpcap_process.wait(timeout=5)
        print(f"\n🛑 dumpcap stopped (PID: {dumpcap_process.pid})")
    except Exception as e:
        print(f"\n⚠️ Failed to stop dumpcap, force kill: {str(e)}")
        dumpcap_process.kill()
    
    # 检测抓包文件
    latest_pcap = get_latest_pcap(PCAP_CAPTURE_DIR, dumpcap_base_pcap_name)
    if latest_pcap:
        file_size = os.path.getsize(latest_pcap) / 1024 / 1024
        print(f"✅ Capture file generated: {latest_pcap} (Size: {file_size:.2f} MB)")
    else:
        print(f"❌ No valid capture file found!")
    
    dumpcap_process = None

def call_pcap2para():
    """调用pcap2para"""
    global dumpcap_base_pcap_name
    if not os.path.exists(PCAP2PARA_EXE):
        print(f"❌ Error: pcap2para.exe not found - {PCAP2PARA_EXE}")
        return False
    
    latest_pcap = get_latest_pcap(PCAP_CAPTURE_DIR, dumpcap_base_pcap_name)
    if not latest_pcap:
        print(f"❌ Error: No valid PCAP file found")
        return False
    print(f"✅ Found latest capture file: {latest_pcap}")
    
    check_dir_writable(ANALYZED_DATA_DIR, "Analysis result")
    pcap_name = Path(latest_pcap).stem
    output_file = os.path.join(ANALYZED_DATA_DIR, f"{pcap_name}_analysis.txt")
    
    # 调用pcap2para
    pcap2para_cmd = [
        PCAP2PARA_EXE,
        "-p", DEFAULT_EXTRACT_PARAM,
        str(latest_pcap),
        "-o", output_file,
        "-d"
    ]
    
    try:
        print("\n📌 Starting pcap2para HTTP analysis...")
        result = subprocess.run(
            pcap2para_cmd,
            cwd=os.path.dirname(PCAP2PARA_EXE),
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            check=True,
            timeout=300
        )
        print("✅ pcap2para analysis completed!")
        print(f"🔍 Result saved to: {output_file}")
        print(f"📝 Tool output: {result.stdout.strip()}")
        
        # HTTP包为0的提示
        if "Valid HTTP packets: 0" in result.stdout:
            print("\n⚠️ No valid HTTP packets detected! Ultimate checks:")
            print("   1. Visited http://www.baidu.com (NOT https://www.baidu.com) during capture")
            print("   2. Selected correct interface (active internet interface: WLAN/Ethernet)")
            print("   3. Closed VPN/proxy/firewall (they encrypt/block HTTP traffic)")
            print("   4. pcap2para only parses HTTP (port 80), not HTTPS (port 443)")
            print("   5. Open capture file with Wireshark to verify HTTP traffic (filter: http)")
        
        # 预览结果
        if os.path.exists(output_file):
            print("\n📊 pcap2para analysis preview:")
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(content if content else "⚠️ Analysis result empty (no matching HTTP parameters)")
        return True
    except subprocess.TimeoutExpired:
        print("❌ pcap2para timeout (5 minutes)")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ pcap2para failed (exit code: {e.returncode})")
        print(f"🔍 Error output: {e.stderr.strip()[:200]}...")
        return False
    except Exception as e:
        print(f"❌ pcap2para analysis failed: {str(e)}")
        return False

def call_common_ip(latest_csv):
    """调用枫叶工具"""
    if not latest_csv:
        print("\n⚠️ No CICFlowMeter CSV file found, skip Common IP analysis...")
        print("💡 CICFlowMeter Mandatory Steps:")
        print("   1. Copy Java command to Administrator CMD and run")
        print("   2. Select EXACT same interface:")
        print(f"      - Number: {selected_interface_info.get('idx', '')}")
        print(f"      - English Name: {selected_interface_info.get('en_name', '')}")
        print(f"      - Device ID: {selected_interface_info.get('device_id', '')}")
        print("   3. Click Start → Capture for 30s → Click Stop → Close CICFlowMeter")
        print("   4. CSV file will be generated at: " + CICFLOWMETER_OUTPUT_DIR)
        return True
    
    if not os.path.exists(COMMON_IP_EXE):
        print(f"❌ Error: common_ip.exe not found - {COMMON_IP_EXE}")
        print(f"💡 Build command: cd C:\\Users\\z1395\\network_trace_system\\ws-traffic-analyze-kit && cargo build --release")
        return False

    try:
        exe_work_dir = os.path.dirname(COMMON_IP_EXE)
        result = subprocess.run(
            [COMMON_IP_EXE, str(latest_csv)],
            cwd=exe_work_dir,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            check=True,
            timeout=300
        )
        print("✅ Common IP analysis completed!")
        print(f"🔍 Tool output: {result.stdout.strip()}")

        print("\n📊 Common IP analysis result:")
        if os.path.exists(RESULT_FILE_PATH):
            with open(RESULT_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(content if content else "⚠️ ip_counts.txt empty")
        else:
            print(f"❌ Error: Result file not found - {RESULT_FILE_PATH}")

    except Exception as e:
        print(f"❌ Common IP analysis failed: {str(e)}")
        return False
    return True

def main():
    # 强制UTF-8输出
    sys.stdout.reconfigure(encoding='utf-8')
    print("======================================================================")
    print("          dumpcap + CICFlowMeter + Common IP + pcap2para Tool")
    print("======================================================================\n")

    # 管理员权限检查
    if not check_admin():
        print("⚠️ Warning: Not running as Administrator! Packet capture will fail")
        print("💡 Fix immediately: Right-click CMD → Run as Administrator → Re-run python main.py\n")

    # 检查抓包驱动（CICFlowMeter必需）
    check_npcap_winpcap()

    # 步骤1：选择网卡（纯英文）
    print("\n📌 Step 1: Select Monitoring Interface (CRITICAL!)")
    global selected_interface
    selected_interface = select_interface_manually()

    # 步骤2：启动dumpcap
    print("\n📌 Step 2: Start dumpcap Packet Capture...")
    dumpcap_started = start_dumpcap_immediately()
    if not dumpcap_started:
        print("⚠️ dumpcap failed to start! Fix capture issues first.")
        input("\nPress Enter to continue with CICFlowMeter steps...")

    # 步骤3：启动CICFlowMeter（精准网卡匹配）
    print("\n📌 Step 3: Start CICFlowMeter (MANDATORY!)")
    check_dir_writable(CICFLOWMETER_OUTPUT_DIR, "CICFlowMeter output")
    cic_work_dir = os.path.dirname(CICFLOWMETER_JAR)
    # 生成CICFlowMeter启动命令（带网卡参数，若支持）
    cic_cmd = (
        f"java -Duser.dir=\"{cic_work_dir}\" "
        f"-Dfile.encoding=UTF-8 "
        f"-jar \"{CICFLOWMETER_JAR}\" "
        f"-o \"{CICFLOWMETER_OUTPUT_DIR}\""
    )
    
    print("\n🔧 Run this command in ADMINISTRATOR CMD to start CICFlowMeter:")
    print(f"   {cic_cmd}")
    
    print("\n📋 CICFlowMeter EXACT Operation Steps (NO SKIPS!):")
    print(f"   1. After startup, select interface by:")
    print(f"      - Number: {selected_interface_info.get('idx', '')}")
    print(f"      - English Name: {selected_interface_info.get('en_name', '')}")
    print(f"      - Device ID: {selected_interface_info.get('device_id', '')}")
    print(f"   2. Verify Output Directory: {CICFLOWMETER_OUTPUT_DIR}")
    print(f"   3. Click [Start] → Visit http://www.baidu.com → Wait 30 seconds")
    print(f"   4. Click [Stop] → Close CICFlowMeter (CSV generated ONLY after Stop)")
    input("   Complete above steps, then press Enter to stop capture and analyze...\n")

    # 步骤4：停止dumpcap
    print("\n📌 Step 4: Stop dumpcap Capture...")
    stop_dumpcap_on_enter()

    # 步骤5：查找CSV文件
    print("\n📌 Step 5: Find CICFlowMeter CSV File...")
    latest_csv = get_latest_csv()
    if not latest_csv:
        print(f"❌ No CSV file found (Main dir: {CICFLOWMETER_OUTPUT_DIR})")
        print("💡 EMERGENCY CHECKS:")
        print("   1. Did you click [Stop] in CICFlowMeter? (CSV generated ONLY after Stop)")
        print("   2. Ran CICFlowMeter in Administrator CMD?")
        print("   3. Selected EXACT same interface as dumpcap?")
        print("   4. Check system dir for CSV: " + CICFLOWMETER_FALLBACK_DIR)
    else:
        print(f"✅ Found latest CSV file: {latest_csv}")

    # 步骤6：枫叶工具分析
    print("\n📌 Step 6: Start Common IP Analysis...")
    call_common_ip(latest_csv)

    # 步骤7：pcap2para分析
    print("\n📌 Step 7: Start pcap2para HTTP Analysis...")
    call_pcap2para()

    # 流程结束
    print("\n🎉 All steps completed!")
    print(f"📂 Capture files: {PCAP_CAPTURE_DIR}")
    print(f"📂 CSV files: {CICFLOWMETER_OUTPUT_DIR}")
    print(f"📂 Analysis results: {ANALYZED_DATA_DIR}")
    print("\n🔍 Final Troubleshooting Checklist:")
    print("   ✅ dumpcap failed: Use WLAN interface + Admin + Close firewall")
    print("   ✅ No CSV: CICFlowMeter Start→Stop + Exact interface match + Admin")
    print("   ✅ No HTTP packets: Visit http://www.baidu.com + WLAN interface")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ User interrupted program, cleaning up dumpcap...")
        stop_dumpcap_on_enter()
    except Exception as e:
        print(f"\n\n❌ Program error: {str(e)}")
        stop_dumpcap_on_enter()
    finally:
        input("\nPress Enter to exit...")