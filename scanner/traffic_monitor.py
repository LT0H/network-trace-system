import subprocess
import time
import threading
import logging
from pathlib import Path
from django.conf import settings
from .models import TrafficAnalysisResult

logger = logging.getLogger(__name__)

class TrafficMonitor:
    """网络流量监听与分析器"""
    
    def __init__(self):
        self.analyzer_path = Path("C:/Users/z1395/network_trace_system/ws-traffic-analyze-kit-main")
        self.is_running = False
        self.thread = None
        self.interface = self._detect_default_interface()
        self.output_dir = Path(settings.BASE_DIR) / "traffic_data"
        self.output_dir.mkdir(exist_ok=True)
        
    def _detect_default_interface(self):
        """自动检测默认网络接口"""
        try:
            # 使用scapy检测默认接口
            from scapy.all import conf
            return conf.iface.name
        except Exception as e:
            logger.warning(f"无法自动检测网络接口: {e}，使用默认值")
            return "Ethernet"  # 默认接口名，可能需要根据系统调整
    
    def start_monitoring(self, duration=None):
        """开始流量监听
        
        Args:
            duration: 监听时长(秒)，None表示持续监听
        """
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
        """停止流量监听"""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join()
        logger.info("已停止网络流量监听")
    
    def _monitor_loop(self, duration):
        """监听循环"""
        start_time = time.time()
        
        while self.is_running:
            # 检查是否达到监听时长
            if duration and (time.time() - start_time) > duration:
                break
                
            # 捕获一小段时间的流量
            capture_file = self._capture_traffic()
            
            if capture_file:
                # 调用分析工具
                self._analyze_traffic(capture_file)
                
            # 短暂休眠，避免过度消耗CPU
            time.sleep(1)
    
    def _capture_traffic(self, capture_seconds=10):
        """捕获网络流量到pcap文件"""
        try:
            timestamp = int(time.time())
            pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
            
            # 使用tcpdump或npcap进行抓包
            cmd = [
                "tcpdump",
                "-i", self.interface,
                "-w", str(pcap_file),
                "-G", str(capture_seconds),  # 抓包时长
                "-W", "1"  # 只保存一个文件
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
    
    def _analyze_traffic(self, pcap_file):
        """调用ws-traffic-analyze-kit工具分析流量"""
        try:
            if not self.analyzer_path.exists():
                logger.error(f"分析工具路径不存在: {self.analyzer_path}")
                return
                
            # 构建分析命令
            cmd = [
                "python",
                str(self.analyzer_path / "main.py"),
                "-f", str(pcap_file),
                "-o", str(self.output_dir / f"analysis_{pcap_file.stem}.json")
            ]
            
            # 执行分析工具
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"流量分析完成: {pcap_file}")
                self._save_analysis_result(pcap_file, result.stdout)
            else:
                logger.error(f"流量分析失败: {result.stderr}")
                
        except Exception as e:
            logger.error(f"流量分析过程出错: {e}")
    
    def _save_analysis_result(self, pcap_file, analysis_output):
        """保存分析结果到数据库"""
        try:
            # 解析分析结果
            import json
            analysis_data = json.loads(analysis_output)
            
            # 保存到数据库
            TrafficAnalysisResult.objects.create(
                pcap_file_path=str(pcap_file),
                analysis_result=analysis_data,
                packet_count=analysis_data.get('total_packets', 0),
                protocol_distribution=analysis_data.get('protocol_distribution', {})
            )
            
            logger.debug(f"已保存流量分析结果")
            
        except Exception as e:
            logger.error(f"保存分析结果失败: {e}")