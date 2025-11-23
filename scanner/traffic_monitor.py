import os
import subprocess
import time
import threading
import logging
from pathlib import Path
from django.conf import settings
from .models import TrafficAnalysisResult

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
        # 创建子目录分别存储两种工具的输出
        self.cic_output_dir = self.output_dir / "cic_results"
        self.cic_output_dir.mkdir(exist_ok=True)
        self.ws_output_dir = self.output_dir / "ws_results"
        self.ws_output_dir.mkdir(exist_ok=True)
        
    def _detect_default_interface(self):
        """自动检测默认网络接口"""
        try:
            # 使用scapy检测默认接口
            from scapy.all import conf
            return conf.iface.name
        except Exception as e:
            logger.warning(f"无法自动检测网络接口: {e}，使用默认值")
            return "Ethernet"  # 默认接口名，可能需要根据系统调整
    
    def start_monitoring(self, duration=None):  # 添加 duration 参数
        try:
            if self.is_running:
                return {"status": "error", "message": "监控已在运行"}
            
            # 启动监听线程时传递 duration 参数
            self.thread = threading.Thread(target=self._monitor_loop, args=(duration,))
            self.thread.daemon = True
            self.thread.start()
            self.is_running = True
            
            # 检查依赖组件
            errors = []
            if not self.cicflowmeter_available:
                errors.append("CICFlowMeter未找到，流量特征提取功能不可用")
            
            if errors:
                return {"status": "partial", "message": "; ".join(errors), "is_running": True}
            return {"status": "success", "message": "监控启动成功", "is_running": True}
        except Exception as e:
            self.is_running = False
            return {"status": "error", "message": str(e), "is_running": False}

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
                # 同时调用两个分析工具
                self._analyze_with_ws_kit(capture_file)
                self._analyze_with_cic_flow_meter(capture_file)
                
            # 短暂休眠，避免过度消耗CPU
            time.sleep(1)
    
    def _capture_traffic(self, capture_seconds=10):
        try:
            timestamp = int(time.time())
            pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
            
            cmd = [
                "dumpcap",  # 替换tcpdump为dumpcap
                "-i", self.interface,  # 指定接口
                "-w", str(pcap_file),  # 输出文件
                "-a", f"duration:{capture_seconds}",  # 抓包时长（秒）
                "-q"  # 安静模式，减少输出
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
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
        """调用ws-traffic-analyze-kit工具分析流量"""
        try:
            if not self.analyzer_path.exists():
                logger.error(f"WS分析工具路径不存在: {self.analyzer_path}")
                return
                
            # 构建分析命令，Rust工具使用cargo运行
            cmd = [
                "cargo", "run",
                "--manifest-path", str(self.analyzer_path / "Cargo.toml"),
                "--",
                "-f", str(pcap_file),
                "-o", str(self.ws_output_dir / f"analysis_{pcap_file.stem}.json")
            ]
            
            # 执行分析工具
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode == 0:
                logger.info(f"WS流量分析完成: {pcap_file}")
                self._save_analysis_result(pcap_file, result.stdout, "ws")
            else:
                logger.error(f"WS流量分析失败: {result.stderr}")
                
        except Exception as e:
            logger.error(f"WS流量分析过程出错: {e}")
    
    def _analyze_with_cic_flow_meter(self, pcap_file):
        """调用CICFlowMeter工具分析流量"""
        try:
            # 检查CICFlowMeter是否存在
            cic_jar = self.cic_flow_meter_path / "target" / "cicflowmeter-1.0.jar"
            if not cic_jar.exists():
                logger.warning(f"CICFlowMeter JAR文件不存在，尝试构建...")
                # 尝试构建CICFlowMeter
                build_cmd = ["./gradlew", "build"] if os.name != "nt" else ["gradlew.bat", "build"]
                build_result = subprocess.run(
                    build_cmd,
                    cwd=str(self.cic_flow_meter_path),
                    capture_output=True,
                    text=True,
                    encoding='utf-8'
                )
                if build_result.returncode != 0:
                    logger.error(f"CICFlowMeter构建失败: {build_result.stderr}")
                    return
            
            # 构建CICFlowMeter分析命令
            output_file = self.cic_output_dir / f"cic_analysis_{pcap_file.stem}.csv"
            cmd = [
                "java", "-jar", str(cic_jar),
                str(pcap_file),
                str(self.cic_output_dir)
            ]
            
            # 执行分析工具
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode == 0:
                logger.info(f"CICFlowMeter分析完成: {pcap_file}")
                self._save_cic_analysis_result(pcap_file, str(output_file))
            else:
                logger.error(f"CICFlowMeter分析失败: {result.stderr}")
                
        except Exception as e:
            logger.error(f"CICFlowMeter分析过程出错: {e}")
    
    def _save_analysis_result(self, pcap_file, analysis_output, analyzer_type):
        """保存分析结果到数据库"""
        try:
            # 解析分析结果
            import json
            analysis_data = json.loads(analysis_output)
            
            # 保存到数据库
            TrafficAnalysisResult.objects.create(
                pcap_file_path=str(pcap_file),
                analyzer_type=analyzer_type,
                analysis_result=analysis_data,
                packet_count=analysis_data.get('total_packets', 0),
                protocol_distribution=analysis_data.get('protocol_distribution', {})
            )
            
            logger.debug(f"已保存{analyzer_type}流量分析结果")
            
        except Exception as e:
            logger.error(f"保存{analyzer_type}分析结果失败: {e}")
    
    def _save_cic_analysis_result(self, pcap_file, csv_file_path):
        """保存CICFlowMeter的CSV分析结果到数据库"""
        try:
            # 读取CSV文件并提取关键信息
            import csv
            with open(csv_file_path, 'r') as f:
                reader = csv.DictReader(f)
                flow_count = sum(1 for row in reader)  # 计算流数量
                
            # 保存到数据库
            TrafficAnalysisResult.objects.create(
                pcap_file_path=str(pcap_file),
                analyzer_type="cic",
                analysis_result={"csv_path": csv_file_path},
                packet_count=0,  # CIC结果中没有总包数，需要单独解析
                protocol_distribution={}
            )
            
            logger.debug(f"已保存CICFlowMeter分析结果: {csv_file_path}")
            
        except Exception as e:
            logger.error(f"保存CICFlowMeter分析结果失败: {e}")