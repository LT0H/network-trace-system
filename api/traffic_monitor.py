import subprocess
import time
import threading
import logging
from pathlib import Path
from django.conf import settings

logger = logging.getLogger(__name__)

class TrafficMonitor:
    """网络流量监听与分析器，整合CICFlowMeter和ws-traffic-analyze-kit"""
    
    def __init__(self):
        self.analyzer_path = Path("C:/Users/z1395/network_trace_system/ws-traffic-analyze-kit-main")
        self.cic_flow_meter_path = Path("C:/Users/z1395/network_trace_system/CICFlowMeter-master")
        self.is_running = False
        self.thread = None
        self.interface = self._detect_default_interface()
        self.output_dir = Path(settings.BASE_DIR) / "traffic_data"
        self.output_dir.mkdir(exist_ok=True)
        self.cic_output_dir = self.output_dir / "cic_results"
        self.cic_output_dir.mkdir(exist_ok=True)
        self.ws_output_dir = self.output_dir / "ws_results"
        self.ws_output_dir.mkdir(exist_ok=True)
        
    def _detect_default_interface(self):
        """自动检测默认网络接口"""
        try:
            from scapy.all import conf
            return conf.iface.name
        except Exception as e:
            logger.warning(f"无法自动检测网络接口: {e}，使用默认值")
            return "Ethernet"
    
    def start_monitoring(self, duration=None):
        if self.is_running:
            logger.warning("流量监听已在运行中")
            return
            
        self.is_running = True
        self.thread = threading.Thread(
            target=self._monitor_loop,
            args=(duration,),
            daemon=True
        )
        self.thread.start()
        logger.info(f"开始在接口 {self.interface} 上监听网络流量")
    
    def stop_monitoring(self):
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        logger.info("已停止网络流量监听")
    
    def _monitor_loop(self, duration):
        start_time = time.time()
        
        while self.is_running:
            if duration and (time.time() - start_time) > duration:
                break
                
            capture_file = self._capture_traffic()
            if capture_file:
                self._analyze_with_ws_kit(capture_file)
                self._analyze_with_cic_flow_meter(capture_file)
                
            time.sleep(1)
    
    def _capture_traffic(self, capture_seconds=10):
        try:
            timestamp = int(time.time())
            pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
            
            cmd = [
                "tcpdump",
                "-i", self.interface,
                "-w", str(pcap_file),
                "-G", str(capture_seconds),
                "-W", "1"
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=capture_seconds + 2
            )
            
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                logger.debug(f"已捕获流量到 {pcap_file}")
                return pcap_file
            else:
                logger.warning(f"捕获流量失败，文件为空或不存在")
                if pcap_file.exists():
                    pcap_file.unlink()
                return None
                
        except Exception as e:
            logger.error(f"流量捕获出错: {e}")
            return None
    
    def _analyze_with_ws_kit(self, pcap_file):
        try:
            if not self.analyzer_path.exists():
                logger.error(f"WS分析工具路径不存在: {self.analyzer_path}")
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
                logger.info(f"WS流量分析完成: {pcap_file}")
            else:
                logger.error(f"WS流量分析失败: {result.stderr}")
                
        except Exception as e:
            logger.error(f"WS流量分析过程出错: {e}")
    
    def _analyze_with_cic_flow_meter(self, pcap_file):
        try:
            cic_jar = self.cic_flow_meter_path / "target" / "cicflowmeter-1.0.jar"
            if not cic_jar.exists():
                logger.warning(f"CICFlowMeter JAR文件不存在，尝试构建...")
                build_cmd = ["gradlew.bat", "build"]
                build_result = subprocess.run(
                    build_cmd,
                    cwd=str(self.cic_flow_meter_path),
                    capture_output=True,
                    text=True
                )
                if build_result.returncode != 0:
                    logger.error(f"CICFlowMeter构建失败: {build_result.stderr}")
                    return
            
            output_file = self.cic_output_dir / f"cic_analysis_{pcap_file.stem}.csv"
            cmd = [
                "java", "-jar", str(cic_jar),
                str(pcap_file),
                str(self.cic_output_dir)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"CICFlowMeter分析完成: {pcap_file}")
            else:
                logger.error(f"CICFlowMeter分析失败: {result.stderr}")