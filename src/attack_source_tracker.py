#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络攻击源定位系统（修复版）
核心功能：自动获取网络接口 + Wireshark抓包 + 枫叶工具（common_ip.exe）分析 + IP溯源
适配说明：兼容Windows系统多编码格式，增强空值容错能力
"""
import subprocess
import os
import sys
import json
import socket
from datetime import datetime
from collections import defaultdict
import ctypes
import re
import struct

# ===================== 全局配置（适配用户目录）=====================
# 根目录
ROOT_DIR = r"C:\Users\z1395\network_trace_system"
# 核心子目录
SRC_DIR = os.path.join(ROOT_DIR, "src")
CATCHED_DIR = os.path.join(ROOT_DIR, "catched_data")
ANALYZED_DIR = os.path.join(ROOT_DIR, "analyzed_data")
IP_DATA_DIR = os.path.join(ROOT_DIR, "ip_data")
MAPLE_ANALYZER_DIR = os.path.join(ROOT_DIR, "ws-traffic-analyze-kit")

# 工具路径
WIRESHARK_PATH = r"C:\Program Files\Wireshark\wireshark.exe"
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
MAPLE_ANALYZER_EXE = os.path.join(MAPLE_ANALYZER_DIR, "common_ip.exe")
QQWRY_DB = os.path.join(IP_DATA_DIR, "qqwry.dat")

# 输出文件命名
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
PCAP_FILE = os.path.join(CATCHED_DIR, f"capture_{TIMESTAMP}.pcap")
MAPLE_OUTPUT_FILE = os.path.join(ANALYZED_DIR, f"maple_analysis_{TIMESTAMP}.txt")
IP_TRACE_FILE = os.path.join(ANALYZED_DIR, f"ip_trace_{TIMESTAMP}.json")

# 白名单/内网IP过滤
WHITELIST_IPS = {"127.0.0.1", "localhost", "0.0.0.0"}
INTERNAL_IP_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", 
                        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

# ===================== 内置纯真IP库解析（无需第三方包）=====================
class QQWryIPParser:
    """内置纯真IP库解析类，无需安装额外依赖"""
    def __init__(self, db_path):
        self.db_path = db_path
        self.fp = None
        self.index_start = 0
        self.index_end = 0
        self.total_index = 0
        self._load_db()

    def _load_db(self):
        """加载qqwry.dat文件"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"纯真IP库文件缺失：{self.db_path}")
        
        self.fp = open(self.db_path, 'rb')
        # 读取索引区起始和结束位置
        self.index_start = struct.unpack('<I', self.fp.read(4))[0]
        self.index_end = struct.unpack('<I', self.fp.read(4))[0]
        self.total_index = (self.index_end - self.index_start) // 7 + 1

    def _ip2int(self, ip):
        """IP转整数"""
        return struct.unpack('<I', socket.inet_aton(ip))[0]

    def _find_index(self, ip_int):
        """二分查找IP对应的索引"""
        left = 0
        right = self.total_index - 1
        while left <= right:
            mid = (left + right) // 2
            self.fp.seek(self.index_start + mid * 7)
            cur_ip = struct.unpack('<I', self.fp.read(4))[0]
            if cur_ip > ip_int:
                right = mid - 1
            else:
                left = mid + 1
        return right

    def _read_string(self, fp):
        """读取字符串（兼容多编码）"""
        s = b''
        while True:
            c = fp.read(1)
            if c == b'\0':
                break
            s += c
        # 优先GBK，失败则UTF-8，最后忽略错误
        try:
            return s.decode('gbk')
        except:
            try:
                return s.decode('utf-8')
            except:
                return s.decode('utf-8', errors='ignore')

    def lookup(self, ip):
        """
        解析IP地址
        :return: (国家, 地区/ISP)
        """
        try:
            ip_int = self._ip2int(ip)
        except:
            return ("未知IP格式", "")
        
        # 查找索引
        idx = self._find_index(ip_int)
        if idx < 0:
            return ("未知IP", "")
        
        # 读取索引记录
        self.fp.seek(self.index_start + idx * 7)
        self.fp.read(4)  # 跳过IP
        record_ptr = struct.unpack('<I', self.fp.read(3) + b'\0')[0]
        
        # 读取记录
        self.fp.seek(record_ptr)
        flag = struct.unpack('<B', self.fp.read(1))[0]
        
        # 处理国家
        if flag == 0x01:  # 国家指向另一个偏移
            self.fp.seek(struct.unpack('<I', self.fp.read(3) + b'\0')[0])
            flag2 = struct.unpack('<B', self.fp.read(1))[0]
            if flag2 == 0x02:  # 再次指向
                country = self._read_string(self.fp)
                self.fp.seek(struct.unpack('<I', self.fp.read(3) + b'\0')[0])
                area = self._read_string(self.fp)
            else:
                self.fp.seek(-1, 1)
                country = self._read_string(self.fp)
                area = self._read_string(self.fp)
        elif flag == 0x02:  # 国家和地区都指向偏移
            country = self._read_string(self.fp)
            self.fp.seek(struct.unpack('<I', self.fp.read(3) + b'\0')[0])
            area = self._read_string(self.fp)
        else:  # 直接读取
            self.fp.seek(-1, 1)
            country = self._read_string(self.fp)
            area = self._read_string(self.fp)
        
        # 清理空值
        country = country.strip() if country else "未知"
        area = area.strip() if area else "未知"
        return (country, area)

    def close(self):
        """关闭文件句柄"""
        if self.fp:
            self.fp.close()

# ===================== 基础工具函数 =====================
def is_admin():
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"[ERROR] 检查管理员权限失败：{str(e)}")
        return False

def init_directories():
    """初始化目录"""
    dirs = [CATCHED_DIR, ANALYZED_DIR, IP_DATA_DIR]
    for dir_path in dirs:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            print(f"[INFO] 初始化目录成功：{dir_path}")
    return True

def init_qqwry_ip_db():
    """初始化纯真IP库（内置解析）"""
    try:
        ip_parser = QQWryIPParser(QQWRY_DB)
        print(f"[INFO] 纯真IP库加载成功：{QQWRY_DB}")
        return ip_parser
    except Exception as e:
        print(f"[ERROR] 加载纯真IP库失败：{str(e)}")
        print(f"[提示] 请确保{QQWRY_DB}文件存在且完整")
        sys.exit(1)

def check_core_dependencies():
    """检查核心依赖"""
    core_deps = [
        (WIRESHARK_PATH, "Wireshark主程序（抓包）"),
        (TSHARK_PATH, "TShark工具（获取网络接口）"),
        (MAPLE_ANALYZER_EXE, "枫叶分析工具（common_ip.exe）"),
        (QQWRY_DB, "纯真IP库（qqwry.dat）")
    ]
    
    missing_deps = []
    for dep_path, dep_name in core_deps:
        if not os.path.exists(dep_path):
            missing_deps.append(f"{dep_name} -> {dep_path}")
    
    if missing_deps:
        print("[ERROR] 以下核心依赖缺失，无法运行：")
        for dep in missing_deps:
            print(f"  - {dep}")
        sys.exit(1)
    else:
        print("[INFO] 所有核心依赖检查通过")
    return True

def get_available_network_interfaces():
    """自动获取可用网络接口（兼容多编码+空值容错）"""
    print("[INFO] 正在检测可用网络接口...")
    try:
        tshark_cmd = [TSHARK_PATH, "-D"]
        # 执行命令，捕获字节流避免编码提前解析错误
        result = subprocess.run(
            tshark_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # 处理stdout，兼容多编码格式
        stdout_data = result.stdout
        try:
            output = stdout_data.decode('gbk', errors='ignore')
        except:
            output = stdout_data.decode('utf-8', errors='ignore')
        
        # 空值判断：避免None调用splitlines
        if not output:
            print("[ERROR] TShark未返回任何接口信息")
            return {}
        
        interfaces = {}
        interface_pattern = re.compile(r'(\d+)\.\s+[^\s]+\s+\((.*?)\)')
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = interface_pattern.match(line)
            if match:
                interface_id = match.group(1)
                interface_name = match.group(2)
                # 过滤环回接口
                if "环回" not in interface_name and "Loopback" not in interface_name:
                    interfaces[interface_name] = interface_id
        
        if not interfaces:
            print("[ERROR] 未检测到可用的非环回网络接口")
            return {}
        
        print("[INFO] 检测到以下可用网络接口：")
        for idx, (iface_name, iface_id) in enumerate(interfaces.items(), 1):
            print(f"  {idx}. {iface_name}（接口ID：{iface_id}）")
        
        return interfaces
    except subprocess.CalledProcessError as e:
        # 处理stderr编码
        stderr_data = e.stderr
        try:
            stderr_msg = stderr_data.decode('gbk', errors='ignore')
        except:
            stderr_msg = stderr_data.decode('utf-8', errors='ignore')
        print(f"[ERROR] 调用TShark获取接口失败：{stderr_msg}")
        return {}
    except Exception as e:
        print(f"[ERROR] 解析网络接口列表失败：{str(e)}")
        return {}

def select_network_interface():
    """选择网络接口（增强容错）"""
    interfaces = get_available_network_interfaces()
    if not interfaces:
        print("[ERROR] 无可用网络接口，程序退出")
        sys.exit(1)
    
    interface_names = list(interfaces.keys())
    default_iface_name = interface_names[0]
    default_iface_id = interfaces[default_iface_name]
    
    try:
        user_choice = input(f"\n[提示] 请选择抓包接口（输入序号，默认1）：").strip()
        if user_choice.isdigit() and 1 <= int(user_choice) <= len(interface_names):
            selected_iface_name = interface_names[int(user_choice)-1]
            selected_iface_id = interfaces[selected_iface_name]
        else:
            selected_iface_name = default_iface_name
            selected_iface_id = default_iface_id
    except:
        # 输入异常时使用默认接口
        selected_iface_name = default_iface_name
        selected_iface_id = default_iface_id
    
    print(f"[INFO] 已选定抓包接口：{selected_iface_name}（ID：{selected_iface_id}）")
    return selected_iface_id

# ===================== 核心功能函数 =====================
def run_wireshark_capture(interface_id, capture_seconds=60):
    """Wireshark静默抓包"""
    print(f"\n[INFO] 开始Wireshark抓包（接口ID：{interface_id}，时长：{capture_seconds}秒）")
    print(f"[INFO] 抓包文件将保存至：{PCAP_FILE}")
    
    wireshark_cmd = [
        WIRESHARK_PATH,
        "-i", interface_id,
        "-w", PCAP_FILE,
        "-a", f"duration:{capture_seconds}",
        "-q",
        "-k"
    ]
    
    try:
        subprocess.run(
            wireshark_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="ignore"
        )
        
        if os.path.exists(PCAP_FILE) and os.path.getsize(PCAP_FILE) > 0:
            file_size = os.path.getsize(PCAP_FILE) / 1024
            print(f"[INFO] Wireshark抓包完成，文件大小：{file_size:.2f} KB")
            return PCAP_FILE
        else:
            print(f"[ERROR] 抓包文件为空或未生成：{PCAP_FILE}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Wireshark抓包失败：{e.stderr[:500]}")
        return None
    except Exception as e:
        print(f"[ERROR] 抓包过程异常：{str(e)}")
        return None

def run_maple_analyzer(pcap_file_path):
    """调用枫叶工具分析PCAP"""
    print(f"\n[INFO] 启动枫叶分析工具：{MAPLE_ANALYZER_EXE}")
    print(f"[INFO] 分析目标：{pcap_file_path}")
    
    maple_cmd = [
        MAPLE_ANALYZER_EXE,
        "-f", pcap_file_path,
        "-o", MAPLE_OUTPUT_FILE
    ]
    
    try:
        result = subprocess.run(
            maple_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            encoding="utf-8",
            errors="ignore"
        )
        
        if os.path.exists(MAPLE_OUTPUT_FILE):
            print(f"[INFO] 枫叶工具分析完成，结果保存至：{MAPLE_OUTPUT_FILE}")
            if result.stdout:
                print(f"[INFO] 枫叶工具输出（前500字符）：{result.stdout[:500]}...")
            return MAPLE_OUTPUT_FILE
        else:
            print(f"[WARNING] 枫叶工具未生成分析结果文件，但执行无报错")
            return None
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] 枫叶工具执行失败（错误码：{e.returncode}）")
        print(f"[WARNING] 错误信息：{e.stderr[:500]}...")
        return None
    except Exception as e:
        print(f"[WARNING] 枫叶工具执行异常：{str(e)}")
        return None

def extract_ips_from_maple_output(maple_file_path):
    """从枫叶工具结果提取IP"""
    if not os.path.exists(maple_file_path):
        print("[WARNING] 枫叶工具分析结果文件缺失，无法提取IP")
        return []
    
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ip_set = set()
    
    try:
        # 兼容多编码读取
        with open(maple_file_path, "rb") as f:
            data = f.read()
        try:
            content = data.decode('gbk', errors='ignore')
        except:
            content = data.decode('utf-8', errors='ignore')
        
        for line in content.splitlines():
            ips = ip_pattern.findall(line)
            for ip in ips:
                if ip in WHITELIST_IPS or ip.startswith(INTERNAL_IP_PREFIXES):
                    continue
                ip_set.add(ip)
        
        ip_list = list(ip_set)
        print(f"[INFO] 从枫叶分析结果中提取到{len(ip_list)}个外网IP待溯源")
        return ip_list
    except Exception as e:
        print(f"[ERROR] 解析枫叶工具结果失败：{str(e)}")
        return []

def trace_ip_address(ip, ip_parser):
    """IP溯源（内置纯真IP库+WHOIS）"""
    trace_result = {
        "ip": ip,
        "hostname": "",
        "geo_location": {
            "country": "",
            "area_isp": ""
        },
        "whois_info": "",
        "trace_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 1. 获取主机名（socket.gethostbyname）
    try:
        trace_result["hostname"] = socket.gethostbyname(ip)
    except Exception as e:
        trace_result["hostname"] = f"解析失败：{str(e)[:30]}"
    
    # 2. 纯真IP库溯源
    try:
        country, area = ip_parser.lookup(ip)
        trace_result["geo_location"]["country"] = country
        trace_result["geo_location"]["area_isp"] = area
    except Exception as e:
        trace_result["geo_location"]["country"] = "未知"
        trace_result["geo_location"]["area_isp"] = f"溯源失败：{str(e)[:30]}"
    
    # 3. WHOIS溯源
    try:
        import whois
        whois_info = whois.whois(ip)
        trace_result["whois_info"] = str(whois_info)[:2000]
    except ImportError:
        trace_result["whois_info"] = "未安装python-whois库，跳过WHOIS查询"
    except Exception as e:
        trace_result["whois_info"] = f"WHOIS查询失败：{str(e)[:30]}"
    
    return trace_result

def batch_trace_ips(ip_list, ip_parser):
    """批量溯源IP"""
    if not ip_list:
        print("[INFO] 无待溯源的IP地址，跳过溯源步骤")
        return None
    
    print(f"\n[INFO] 开始批量溯源{len(ip_list)}个IP地址...")
    trace_results = {}
    for idx, ip in enumerate(ip_list, 1):
        print(f"[INFO] 溯源进度 {idx}/{len(ip_list)} -> {ip}")
        trace_results[ip] = trace_ip_address(ip, ip_parser)
    
    try:
        with open(IP_TRACE_FILE, "w", encoding="utf-8") as f:
            json.dump(trace_results, f, ensure_ascii=False, indent=4)
        print(f"[INFO] IP溯源完成，结果保存至：{IP_TRACE_FILE}")
        return IP_TRACE_FILE
    except Exception as e:
        print(f"[ERROR] 保存IP溯源结果失败：{str(e)}")
        return None

# ===================== 主程序入口 =====================
def main():
    """主流程"""
    print("="*70)
    print("[INFO] 网络攻击源定位系统（修复版）启动")
    print("[INFO] 核心功能：Wireshark抓包 + 枫叶工具分析 + IP溯源")
    print("="*70)
    
    # 前置检查
    if not is_admin():
        print("[ERROR] 请以管理员身份运行本程序（Wireshark抓包需要管理员权限）")
        sys.exit(1)
    
    init_directories()
    check_core_dependencies()
    ip_parser = init_qqwry_ip_db()
    
    # 选择接口
    interface_id = select_network_interface()
    
    # 抓包
    capture_seconds = 60
    pcap_file = run_wireshark_capture(interface_id, capture_seconds)
    if not pcap_file:
        ip_parser.close()
        print("[ERROR] 抓包失败，程序退出")
        sys.exit(1)
    
    # 枫叶工具分析
    maple_output = run_maple_analyzer(pcap_file)
    
    # IP提取与溯源
    ip_list = extract_ips_from_maple_output(maple_output)
    batch_trace_ips(ip_list, ip_parser)
    
    # 关闭IP库
    ip_parser.close()
    
    # 总结
    print("\n" + "="*70)
    print("[INFO] 程序运行完成，生成文件列表：")
    print(f"  1. Wireshark抓包文件：{PCAP_FILE}")
    if maple_output:
        print(f"  2. 枫叶工具分析结果：{maple_output}")
    if os.path.exists(IP_TRACE_FILE):
        print(f"  3. IP溯源结果文件：{IP_TRACE_FILE}")
    print("="*70)

if __name__ == "__main__":
    if os.name != "nt":
        print("[ERROR] 本程序仅支持Windows操作系统")
        sys.exit(1)
    main()