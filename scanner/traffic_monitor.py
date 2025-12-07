import os
import subprocess
import time
import threading
import logging
from pathlib import Path
from django.conf import settings
from .models import TrafficAnalysis

logger = logging.getLogger(__name__)

class TrafficMonitor:
    """基于dumpcap的流量捕获与WS工具分析器"""
    
    def __init__(self):
        # 配置路径（按需求固定）
        self.pcap_dir = Path(settings.BASE_DIR) / "data" / "catched_data"  # 抓包文件存储路径
        self.ws_analyzer_path = Path("C:/Users/z1395/network_trace_system/ws-traffic-analyze-kit-main/target/debug/ws_traffic_analyze_kit.exe")  # 编译后的WS工具
        self.ws_output_dir = Path(settings.BASE_DIR) / "data" / "ws_analysis_results"  # WS分析结果路径
        
        # 初始化目录
        self._init_directories()
        
        # 状态管理
        self.is_running = False
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._analysis_threads = []
        self.interface = self._detect_default_interface()  # 自动检测接口
        self.capture_duration = 10  # 每次抓包时长（秒）
        self.max_analysis_threads = 5  # 最大并发分析线程
    
    def _init_directories(self):
        """确保存储目录存在"""
        self.pcap_dir.mkdir(exist_ok=True, parents=True)
        self.ws_output_dir.mkdir(exist_ok=True, parents=True)
        logger.info(f"抓包文件路径: {self.pcap_dir}")
        logger.info(f"WS分析结果路径: {self.ws_output_dir}")
    
    def _detect_default_interface(self):
        """自动检测Windows默认网络接口（依赖dumpcap）"""
        try:
            # 通过dumpcap -D获取所有接口
            result = subprocess.run(
                ["dumpcap", "-D"], capture_output=True, text=True, encoding="utf-8"
            )
            interfaces = result.stdout.splitlines()
            if interfaces:
                # 取第一个非环回接口（通常索引0为默认）
                for iface in interfaces:
                    if "Loopback" not in iface and "环回" not in iface:
                        return iface.split(" ")[0]  # 提取接口索引
            return "1"  # 默认接口索引
        except Exception as e:
            logger.warning(f"接口检测失败，使用默认接口: {e}")
            return "1"
    
    def start_monitoring(self, duration=None):
        """启动流量监控（抓包+分析）"""
        with self._lock:
            if self.is_running:
                return {"status": "warning", "message": "监控已运行"}
            try:
                self.is_running = True
                self._monitor_thread = threading.Thread(
                    target=self._monitoring_loop,
                    args=(duration or 3600,),  # 默认监控1小时
                    daemon=True
                )
                self._monitor_thread.start()
                return {"status": "success", "message": f"监控启动：接口={self.interface}"}
            except Exception as e:
                self.is_running = False
                logger.error(f"启动失败: {e}")
                return {"status": "error", "message": str(e)}
    
    def stop_monitoring(self):
        """停止监控"""
        with self._lock:
            if not self.is_running:
                return {"status": "warning", "message": "监控未运行"}
            self.is_running = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=10)
            # 等待分析线程结束
            for thread in self._analysis_threads:
                thread.join(timeout=5)
            self._analysis_threads.clear()
            return {"status": "success", "message": "监控已停止"}
    
    def _monitoring_loop(self, total_duration):
        """监控主循环：定时抓包并触发分析"""
        start_time = time.time()
        while self.is_running and (time.time() - start_time) < total_duration:
            pcap_file = self._capture_traffic()
            if pcap_file:
                self._start_analysis_thread(pcap_file)
            time.sleep(1)  # 避免密集循环
    
    def _capture_traffic(self):
        """使用dumpcap抓取pcap文件"""
        try:
            # 检查dumpcap是否可用（依赖Wireshark）
            subprocess.run(["dumpcap", "-h"], capture_output=True, check=True)
            
            # 生成带时间戳的文件名
            timestamp = int(time.time())
            pcap_file = self.pcap_dir / f"capture_{timestamp}.pcap"
            
            # 执行抓包命令（指定时长、接口、输出文件）
            cmd = [
                "dumpcap",
                "-i", self.interface,  # 接口索引
                "-w", str(pcap_file),  # 输出文件
                "-a", f"duration:{self.capture_duration}",  # 抓包时长
                "-q"  # 静默模式
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.capture_duration + 5  # 超时时间
            )
            
            if result.returncode != 0:
                logger.error(f"抓包失败: {result.stderr}")
                return None
            
            # 验证文件有效性
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                logger.info(f"抓包成功: {pcap_file}（大小: {pcap_file.stat().st_size}字节）")
                return pcap_file
            else:
                logger.warning("抓包文件为空，已删除")
                if pcap_file.exists():
                    pcap_file.unlink()
                return None
        
        except FileNotFoundError:
            logger.error("未找到dumpcap，请确保Wireshark已安装并添加到系统PATH")
            return None
        except Exception as e:
            logger.error(f"抓包异常: {e}")
            return None
    
    def _start_analysis_thread(self, pcap_file):
        """启动异步线程执行WS分析"""
        # 控制并发线程数
        while len(self._analysis_threads) >= self.max_analysis_threads:
            self._analysis_threads = [t for t in self._analysis_threads if t.is_alive()]
            time.sleep(1)
        
        thread = threading.Thread(
            target=self._analyze_with_ws,
            args=(pcap_file,),
            daemon=True
        )
        thread.start()
        self._analysis_threads.append(thread)
    
    def _analyze_with_ws(self, pcap_file):
        """使用编译好的WS工具分析pcap文件"""
        try:
            if not self.ws_analyzer_path.exists():
                logger.error(f"WS分析工具不存在: {self.ws_analyzer_path}")
                return
            
            # 生成分析结果文件名
            output_file = self.ws_output_dir / f"analysis_{pcap_file.stem}.json"
            
            # 调用WS工具（直接运行编译后的exe）
            cmd = [
                str(self.ws_analyzer_path),
                "-f", str(pcap_file),  # 输入pcap文件
                "-o", str(output_file)  # 输出结果文件
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and output_file.exists():
                logger.info(f"WS分析完成: {output_file}")
                # 保存结果到数据库
                with open(output_file, "r") as f:
                    analysis_data = json.load(f)
                TrafficAnalysis.objects.create(
                    analysis_type="ws",
                    result_summary={
                        "total_packets": analysis_data.get("total_packets", 0),
                        "protocol_distribution": analysis_data.get("protocol_distribution", {})
                    },
                    detailed_report=json.dumps(analysis_data, indent=2)
                )
            else:
                logger.error(f"WS分析失败: {result.stderr}")
        
        except Exception as e:
            logger.error(f"WS分析异常: {e}")