"""网络流量监听与分析API，仅保留dumpcap抓包和WS分析功能"""
import time
import threading
import subprocess
from pathlib import Path
import logging  # 替换 import logger
import settings

class TrafficMonitor:
    """网络流量监听与分析器API，仅使用dumpcap抓包和ws-traffic-analyze-kit分析"""
    
    def __init__(self):
        self.analyzer_path = Path("C:/Users/z1395/network_trace_system/ws-traffic-analyze-kit-main")
        self.pcap_dir = Path("network_trace_system/data/catched_data")  # 新的抓包存储目录
        self.ws_output_dir = self.pcap_dir.parent / "ws_results"  # WS分析结果目录
        
        # 初始化目录
        self.pcap_dir.mkdir(exist_ok=True, parents=True)
        self.ws_output_dir.mkdir(exist_ok=True)
        
        # 状态管理
        self.is_running = False
        self.thread = None
        self.interface = self._detect_default_interface()
    
    def _detect_default_interface(self):
        """自动检测默认网络接口"""
        try:
            from scapy.all import conf
            return conf.iface.name
        except Exception as e:
            logging.warning(f"无法自动检测网络接口: {e}，使用默认值")  # 替换 logger
            return "Ethernet"
    
    def start_monitoring(self, duration=None):
        """启动流量监控"""
        if self.is_running:
            logging.warning("流量监听已在运行中")  # 替换 logger
            return
            
        self.is_running = True
        self.thread = threading.Thread(
            target=self._monitor_loop,
            args=(duration,),
            daemon=True
        )
        self.thread.start()
        logging.info(f"开始在接口 {self.interface} 上监听网络流量，pcap存储至 {self.pcap_dir}")  # 替换 logger
    
    def stop_monitoring(self):
        """停止流量监控"""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        logging.info("已停止网络流量监听")  # 替换 logger
    
    def _monitor_loop(self, duration):
        """监控主循环"""
        start_time = time.time()
        
        while self.is_running:
            if duration and (time.time() - start_time) > duration:
                break
                
            capture_file = self._capture_traffic()
            if capture_file:
                self._analyze_with_ws_kit(capture_file)  # 仅保留WS分析
                
            time.sleep(1)
    
    def _capture_traffic(self, capture_seconds=10):
        """使用dumpcap抓包（替换原tcpdump，保持Windows兼容性）"""
        try:
            timestamp = int(time.time())
            pcap_file = self.pcap_dir / f"capture_{timestamp}.pcap"
            
            # 使用dumpcap替代tcpdump，确保Windows兼容性
            cmd = [
                "dumpcap",
                "-i", self.interface,
                "-w", str(pcap_file),
                "-a", f"duration:{capture_seconds}",
                "-q"
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=capture_seconds + 2
            )
            
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                logging.debug(f"已捕获流量到 {pcap_file}")  # 替换 logger
                return pcap_file
            else:
                logging.warning(f"捕获流量失败，文件为空或不存在")  # 替换 logger
                if pcap_file.exists():
                    pcap_file.unlink()
                return None
                
        except Exception as e:
            logging.error(f"流量捕获出错: {e}")  # 替换 logger
            return None
    
    def _analyze_with_ws_kit(self, pcap_file):
        """使用ws-traffic-analyze-kit分析pcap文件"""
        try:
            if not self.analyzer_path.exists():
                logging.error(f"WS分析工具路径不存在: {self.analyzer_path}")  # 替换 logger
                return
                
            cmd = [
                "cargo", "run",
                "--manifest-path", str(self.analyzer_path / "Cargo.toml"),
                "--",
                "-f", str(pcap_file),
                "-o", str(self.ws_output_dir / f"analysis_{pcap_file.stem}.json")
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logging.info(f"WS流量分析完成: {pcap_file}")  # 替换 logger
            else:
                logging.error(f"WS流量分析失败: {result.stderr}")  # 替换 logger
                
        except Exception as e:
            logging.error(f"WS流量分析过程出错: {e}")  # 替换 logger