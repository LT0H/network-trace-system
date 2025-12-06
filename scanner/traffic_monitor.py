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
        # 读取配置（适配你指定的绝对路径，无需额外调整）
        self.analyzer_path = Path(settings.WS_ANALYZER_PATH)
        self.cic_flow_meter_path = Path(settings.CIC_FLOW_METER_PATH)
        self.pcap_dir = Path(settings.PCAP_SAVE_PATH)  # 固定pcap存放路径
        self.cic_output_dir = Path(settings.CIC_CSV_SAVE_PATH)  # 固定CIC-CSV存放路径
        self.ws_output_dir = Path(settings.WS_RESULT_SAVE_PATH)  # 固定WS结果存放路径
        
        # 初始化目录（不存在则自动创建，避免报错）
        self._init_directories()
        
        # 状态管理
        self.is_running = False
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._analysis_threads = []
        self.interface = self._detect_default_interface()
        
        # 配置参数（从settings读取）
        self.capture_duration = settings.CAPTURE_DURATION
        self.max_analysis_threads = 5
        
    def _init_directories(self):
        """初始化指定存放目录（确保路径对应你设置的位置）"""
        self.pcap_dir.mkdir(exist_ok=True)
        self.cic_output_dir.mkdir(exist_ok=True, parents=True)
        self.ws_output_dir.mkdir(exist_ok=True, parents=True)
        
    def _detect_default_interface(self):
        """自动检测Windows默认网络接口，避免手动配置"""
        try:
            # 优先用netifaces检测（需先装：pip install netifaces）
            import netifaces
            default_gateway = netifaces.gateways().get('default', {})
            if netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][1]
            
            # 如默认网关检测失败，列出所有可用接口供选择
            interfaces = netifaces.interfaces()
            logger.info(f"可用网络接口: {interfaces}")
            if interfaces:
               return interfaces[0]  # 返回第一个可用接口
            
        except ImportError:
            logger.warning("未安装netifaces模块，请运行 'pip install netifaces' 安装")
        except Exception as e:
            logger.warning(f"自动检测接口失败: {e}")
        
        # 检测失败时，提供手动配置指引
        logger.warning("请手动配置网络接口，可用接口可通过 'dumpcap -D' 命令查看")
        return "Ethernet"  # 默认值
    
    def start_monitoring(self, duration=None):
        """启动监听：同时抓pcap、跑CIC、跑WS"""
        with self._lock:
            if self.is_running:
                return {"status": "warning", "message": "监控已运行"}
            try:
                self.is_running = True
                self._monitor_thread = threading.Thread(
                    target=self._monitoring_loop, 
                    args=(duration or settings.MONITOR_DURATION,),
                    daemon=True
                )
                self._monitor_thread.start()
                logger.info(f"监听启动：接口={self.interface}，pcap存={self.pcap_dir}")
                return {"status": "success", "message": "监控启动成功"}
            except Exception as e:
                self.is_running = False
                logger.error(f"启动失败: {e}")
                return {"status": "error", "message": str(e)}
    
    def stop_monitoring(self):
        """停止监听+分析线程"""
        with self._lock:
            if not self.is_running:
                return {"status": "warning", "message": "监控未运行"}
            self.is_running = False
            self._monitor_thread.join(timeout=10)
            self._monitor_thread = None
            # 等待分析线程结束
            for thread in self._analysis_threads:
                thread.join(timeout=5)
            self._analysis_threads.clear()
            logger.info("监控已停止")
            return {"status": "success", "message": "监控停止成功"}
    
    def _monitoring_loop(self, duration):
        """监听主循环：定时抓包+触发分析"""
        start_time = time.time()
        while self.is_running:
            if (time.time() - start_time) > duration:
                logger.info(f"达到监控时长{duration}秒，即将停止")
                break
            # 抓pcap文件
            capture_file = self._capture_traffic()
            if capture_file:
                # 异步分析（不阻塞抓包）
                self._start_analysis_thread(capture_file)
            time.sleep(1)
    
    def _capture_traffic(self):
        """用dumpcap抓包，存到指定pcap目录"""
        try:
            # 检查dumpcap是否可用
            subprocess.run(["dumpcap", "-h"], capture_output=True, check=True)
        
            timestamp = int(time.time())
            pcap_file = self.pcap_dir / f"capture_{timestamp}.pcap"
        
            # 检查接口是否存在
            interfaces = subprocess.run(
                ["dumpcap", "-D"], capture_output=True, text=True, encoding='utf-8'
            ).stdout
            
            if self.interface not in interfaces:
                logger.error(f"接口 {self.interface} 不存在，可用接口: {interfaces}")
                return None
                
            # dumpcap命令（Windows兼容，静默抓包）
            cmd = [
                "dumpcap", "-i", self.interface, "-w", str(pcap_file),
                "-a", f"duration:{self.capture_duration}", "-q"
            ]
            
            # 执行命令并捕获详细错误信息
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding='utf-8',
                timeout=self.capture_duration + 5
            )
            
            if result.returncode != 0:
                logger.error(f"抓包命令错误输出: {result.stderr}")
                return None
                
            # 验证文件有效（非空）
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                logger.info(f"抓包成功：{pcap_file}（大小：{pcap_file.stat().st_size}字节）")
                return pcap_file
            else:
                logger.warning(f"抓包文件为空，删除无效文件")
                if pcap_file.exists():
                    pcap_file.unlink()
                return None
                
        except FileNotFoundError:
            logger.error("未找到dumpcap程序，请确保Wireshark已安装并添加到系统PATH")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"抓包超时（超过{self.capture_duration + 5}秒）")
            return None
        except Exception as e:
            logger.error(f"抓包失败: {e}")
            return None
    
    def _start_analysis_thread(self, pcap_file):
        """启动线程：并行跑CIC和WS分析"""
        # 限制并发线程数
        while len(self._analysis_threads) >= self.max_analysis_threads:
            self._analysis_threads = [t for t in self._analysis_threads if t.is_alive()]
            time.sleep(1)
        thread = threading.Thread(
            target=self._analyze_captured_file, args=(pcap_file,), daemon=True
        )
        thread.start()
        self._analysis_threads.append(thread)
    
    def _analyze_captured_file(self, pcap_file):
        """核心：用CIC生成CSV、用WS生成结果，分别存指定目录"""
        try:
            # 并行执行两个分析（互不阻塞）
            threading.Thread(target=self._analyze_with_cic, args=(pcap_file,), daemon=True).start()
            threading.Thread(target=self._analyze_with_ws, args=(pcap_file,), daemon=True).start()
        except Exception as e:
            logger.error(f"分析文件{pcap_file.name}失败: {e}")
    
    def _analyze_with_cic(self, pcap_file):
        try:
            # 修正JAR文件路径：指向build/libs目录下的实际JAR文件
            cic_jar = Path("C:/Users/z1395/network_trace_system/CICFlowMeter-master/build/libs/CICFlowMeter-4.0.jar")
            logger.debug(f"检查CICFlowMeter JAR路径: {cic_jar}")
            
            if not cic_jar.exists():
                # 如果主JAR不存在，尝试ZeroDep版本
                cic_jar =Path("C:/Users/z1395/network_trace_system/CICFlowMeter-master/build/libs/CICFlowMeter-ZeroDep.jar")
                logger.debug(f"尝试ZeroDep版本JAR路径: {cic_jar}")
                if not cic_jar.exists():
                    logger.warning(f"CICFlowMeter JAR文件不存在，尝试构建...")
                    # 构建命令保持不变
                    build_cmd = [
                        "gradle",  
                        "build", 
                        "--warning-mode", "none"
                    ]
                    build_result = subprocess.run(
                        build_cmd,
                        cwd=str(self.cic_flow_meter_path),
                        capture_output=True,
                        text=True
                    )
                    logger.debug(f"构建输出: {build_result.stdout}")
                    logger.debug(f"构建错误: {build_result.stderr}")
                    
                    if build_result.returncode != 0:
                        logger.error(f"CICFlowMeter构建失败，返回码: {build_result.returncode}")
                        return
                    # 构建后再次检查JAR是否存在
                    if not cic_jar.exists():
                        logger.error(f"构建后仍未找到JAR文件: {cic_jar}")
                        return
            
            # 执行CICFlowMeter分析（使用正确的JAR路径）
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
                
        except Exception as e:
            logger.error(f"CICFlowMeter分析过程出错: {e}", exc_info=True)
        
    def _analyze_with_ws(self, pcap_file):
        """WS分析：结果存到指定目录"""
        try:
            # 验证WS工具路径（需确保有Cargo.toml）
            cargo_toml = self.analyzer_path / "Cargo.toml"
            if not cargo_toml.exists():
                logger.error(f"WS工具路径无效：无Cargo.toml（{cargo_toml}）")
                return
            # WS输出文件名（和pcap同名，便于关联）
            ws_result_file = self.ws_output_dir / f"ws_result_{pcap_file.stem}.json"
            # WS命令（cargo run执行，Windows兼容）
            cmd = [
                "cargo", "run", "--manifest-path", str(cargo_toml),
                "--", "-f", str(pcap_file), "-o", str(ws_result_file)
            ]
            subprocess.run(
                cmd, capture_output=True, text=True, encoding='utf-8', check=True
            )
            if ws_result_file.exists():
                logger.info(f"WS分析成功：结果存{ws_result_file}")
                # 存数据库（可选，保留原逻辑）
                self._save_ws_result(pcap_file, ws_result_file)
            else:
                logger.warning(f"WS未生成结果文件")
        except Exception as e:
            logger.error(f"WS分析失败: {e}")
    
    def _save_cic_result(self, pcap_file, csv_file):
        """CIC结果存数据库（保留原逻辑，可选）"""
        try:
            import csv
            with open(csv_file, 'r', encoding='utf-8') as f:
                flow_count = sum(1 for _ in csv.DictReader(f)) - 1  # 减表头
            TrafficAnalysisResult.objects.create(
                pcap_file_path=str(pcap_file),
                analyzer_type="cic",
                analysis_result={"csv_path": str(csv_file), "flow_count": flow_count},
                packet_count=0,
                protocol_distribution={}
            )
        except Exception as e:
            logger.error(f"CIC结果存库失败: {e}")
    
    def _save_ws_result(self, pcap_file, ws_file):
        """WS结果存数据库（保留原逻辑，可选）"""
        try:
            import json
            with open(ws_file, 'r', encoding='utf-8') as f:
                ws_data = json.load(f)
            TrafficAnalysisResult.objects.create(
                pcap_file_path=str(pcap_file),
                analyzer_type="ws",
                analysis_result=ws_data,
                packet_count=ws_data.get('total_packets', 0),
                protocol_distribution=ws_data.get('protocol_distribution', {})
            )
        except Exception as e:
            logger.error(f"WS结果存库失败: {e}")