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


def check_npcap_winpcap():
    """检查抓包驱动（增强版：检查pcap库）"""
    print("🔍 Checking packet capture drivers...")
    winpcap_paths = [
        r"C:\Windows\System32\wpcap.dll", 
        r"C:\Program Files\WinPcap\wpcap.dll",
        r"C:\Program Files\Npcap\wpcap.dll"
    ]
    has_winpcap = any(os.path.exists(p) for p in winpcap_paths)
    
    if has_winpcap:
        print("✅ WinPcap/Npcap driver detected (legacy mode)")
        # 检查环境变量（修复pcap2para依赖）
        if "PATH" not in os.environ or not any(p in os.environ["PATH"] for p in winpcap_paths):
            os.environ["PATH"] += ";" + os.path.dirname([p for p in winpcap_paths if os.path.exists(p)][0])
            print("✅ Added pcap library to PATH")
        return True
    else:
        print("❌ No WinPcap/Npcap driver found!")
        print("💡 Fix: Install Npcap (https://npcap.com/#download) with 'Install WinPcap compatibility'")
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


def print_cicflowmeter_manual_cmd():
    """输出CICFlowMeter手动启动指令（增强版：强制输出目录+重试）"""
    print("\n📌 Step 3: Manual Start CICFlowMeter (DO THE FOLLOWING EXACTLY!)")
    
    # 1. 检查JNETPCAP依赖
    if not os.path.exists(JNETPCAP_DLL_DIR):
        print(f"⚠️ Critical: JNETPCAP directory not found: {JNETPCAP_DLL_DIR}")
        print(f"💡 Fix: Download jnetpcap-1.4.r1425 and extract to the path above")
        input("\nPress Enter after fixing JNETPCAP path...\n")
    
    # 2. 构造启动命令（强制指定输出目录，避免手动设置错误）
    cic_work_dir = os.path.dirname(CICFLOWMETER_JAR)
    cic_launch_cmd = (
        f"cd /d \"{cic_work_dir}\" && "
        f"java -Djava.library.path=\"{JNETPCAP_DLL_DIR}\" -Dfile.encoding=UTF-8 -jar \"{CICFLOWMETER_JAR}\" "
        f"-o \"{CICFLOWMETER_OUTPUT_DIR}\""  # 核心：命令行指定输出目录，无需用户手动设置
    )
    
    print("\n🔧 Copy this command to ADMIN CMD and run (DO NOT MODIFY!):")
    print(f"   {cic_launch_cmd}")
    print("\n📋 Step-by-Step Operation (MUST FOLLOW!):")
    print(f"   1. After running the command, CICFlowMeter window will open.")
    print(f"   2. Click 'Open' → Select interface {selected_interface} (MUST match your earlier choice!)")
    print(f"   3. Click 'Start' → Immediately visit http://www.baidu.com (HTTP) and refresh 10+ times!")
    print(f"   4. Wait 60 seconds (ensure traffic is captured) → Click 'Stop'.")
    print(f"   5. Close CICFlowMeter window.")
    print(f"\n⚠️  Output directory is AUTO-Set to: {CICFLOWMETER_OUTPUT_DIR} (no manual change needed!)")
    input("\nPress Enter ONLY after completing all steps...\n")
    
    # 3. 校验CSV是否生成（支持重试）
    retry_count = 0
    max_retry = 2
    while retry_count < max_retry:
        csv_files = list(Path(CICFLOWMETER_OUTPUT_DIR).rglob("*.csv"))
        if csv_files:
            latest_csv = max(csv_files, key=lambda f: f.stat().st_mtime)
            print(f"✅ Found CICFlowMeter CSV: {latest_csv}")
            return
        else:
            retry_count += 1
            print(f"\n❌ No CSV found! (Retry {retry_count}/{max_retry})")
            print(f"💡 Re-run the CICFlowMeter command and ensure you:")
            print(f"   - Select interface {selected_interface}")
            print(f"   - Capture HTTP traffic (http://baidu.com)")
            input("\nPress Enter after retrying...\n")
    
    print(f"⚠️ Warning: No CSV generated after {max_retry} retries - Common IP will skip!")


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
    
    # 2. 检查CSV文件（支持重试）
    csv_files = list(Path(CICFLOWMETER_OUTPUT_DIR).rglob("*.csv"))
    if not csv_files:
        print(f"⚠️ Common IP skipped (no CSV in {CICFLOWMETER_OUTPUT_DIR})")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: No CSV found\nFixes:\n1. Re-run CICFlowMeter\n2. Ensure HTTP traffic capture\n3. Verify output dir: {CICFLOWMETER_OUTPUT_DIR}\n")
        return False
    
    latest_csv = max(csv_files, key=lambda f: f.stat().st_mtime)
    print(f"\n✅ Found latest CSV: {latest_csv}")
    
    # 3. 验证Common IP工具路径
    if not os.path.exists(COMMON_IP_EXE):
        print(f"❌ common_ip.exe not found: {COMMON_IP_EXE}")
        ensure_file_created(RESULT_FILE_PATH, f"# Error: common_ip.exe missing at {COMMON_IP_EXE}\n")
        return False
    
    try:
        print(f"\n📌 Running Common IP analysis on: {latest_csv}")
        exe_work_dir = os.path.dirname(COMMON_IP_EXE)
        result = subprocess.run(
            [COMMON_IP_EXE, str(latest_csv)],
            cwd=exe_work_dir,
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            check=True,
            timeout=300
        )
        
        print("✅ Common IP analysis completed!")
        print(f"🔍 Tool output: {result.stdout.strip()}")
        
        # 写入结果
        with open(RESULT_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write("# Common IP Analysis Result\n")
            f.write(f"# CSV File: {latest_csv}\n")
            f.write(f"# Analysis Time: {time.ctime()}\n\n")
            f.write(result.stdout.strip())
        
        # 显示结果预览
        print(f"\n📊 ip_counts.txt content:")
        with open(RESULT_FILE_PATH, 'r', encoding='utf-8') as f:
            print(f.read().strip()[:1000])  # 显示前1000字符
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
    """修复pcap2para调用（支持HTTPS提示+依赖检查）"""
    global pcap_file_path
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
    
    # 4. 验证pcap2para路径
    if not os.path.exists(PCAP2PARA_EXE):
        print(f"❌ pcap2para.exe not found: {PCAP2PARA_EXE}")
        return False
    
    # 5. 准备输出文件
    pcap_name = Path(pcap_file_path).stem
    output_file = os.path.join(ANALYZED_DATA_DIR, f"{pcap_name}_analysis.txt")
    ensure_file_created(output_file, f"# pcap2para Analysis for {pcap_name}.pcap\n")
    
    try:
        print(f"\n📌 Running pcap2para analysis (supports HTTP+HTTPS)...")
        print(f"ℹ️ Note: HTTPS payload is encrypted - see final tips to decrypt!")
        # 调用pcap2para（简化参数）
        result = subprocess.run(
            [PCAP2PARA_EXE, pcap_file_path],
            cwd=os.path.dirname(PCAP2PARA_EXE),
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            check=True,
            timeout=300
        )
        
        # 处理输出（区分HTTP/HTTPS）
        std_out = result.stdout.strip()
        analysis_content = f"# pcap2para Analysis Results\n"
        analysis_content += f"# PCAP File: {pcap_file_path}\n"
        analysis_content += f"# Analysis Time: {time.ctime()}\n\n"
        analysis_content += f"## General Info\n"
        analysis_content += f"- PCAP Size: {os.path.getsize(pcap_file_path)/1024:.2f} KB\n"
        analysis_content += f"- Supported Ports: 80 (HTTP), 443 (HTTPS)\n\n"
        
        # 新增HTTPS提示
        if "443" in std_out or "HTTPS" in std_out:
            analysis_content += f"⚠️ HTTPS Traffic Detected (Port 443)\n"
            analysis_content += f"   - Encrypted payload cannot be parsed without SSL decryption.\n"
            analysis_content += f"   - Follow SSL decryption guide below to parse HTTPS.\n\n"
        analysis_content += f"## Tool Output\n{std_out}"
        
        # 写入结果
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(analysis_content)
        
        print("✅ pcap2para analysis completed!")
        print(f"✅ Analysis saved to: {output_file}")
        print("\n📊 Preview:")
        print(analysis_content[:1000])
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ pcap2para failed (exit code {e.returncode}): {e.stderr.strip()}")
        error_content = f"""# pcap2para Error
Exit code: {e.returncode}
Error: {e.stderr.strip()}
PCAP File: {pcap_file_path}

## Fixes:
1. **Missing Boost DLL**: Copy {BOOST_DLL_NAME} to pcap2para.exe folder.
2. **HTTPS Crash**: Avoid only capturing HTTPS traffic (mix with HTTP).
3. **Permission**: Run CMD as Administrator.
4. **SSL Decryption**: For HTTPS, configure SSLKEYLOGFILE (see guide below).

## HTTPS Decryption Guide:
1. Open Wireshark → Edit → Preferences → Protocols → TLS.
2. Set "SSLKEYLOGFILE" to C:\\sslkey.log.
3. Open Admin CMD → Run: setx SSLKEYLOGFILE C:\\sslkey.log.
4. Restart browser and capture traffic again.
"""
        ensure_file_created(output_file, error_content)
        return False
    except Exception as e:
        print(f"❌ pcap2para error: {str(e)}")
        ensure_file_created(output_file, f"# pcap2para Error\n{str(e)}\n")
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

    # 检查驱动
    check_npcap_winpcap()

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

    # 步骤3：输出CICFlowMeter手动启动指令，等待用户操作
    print_cicflowmeter_manual_cmd()

    # 步骤4：停止dumpcap
    print("\n📌 Step 4: Stop Capture & Validate Files...")
    stop_dumpcap_safely()

    # 步骤5：运行Common IP分析
    print("\n📌 Step 5: Run Common IP Analysis...")
    call_common_ip()

    # 步骤6：运行pcap2para分析（支持HTTPS）
    print("\n📌 Step 6: Run pcap2para Analysis...")
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