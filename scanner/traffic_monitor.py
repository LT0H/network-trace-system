import time
import threading
import subprocess
from pathlib import Path
import logging  
from django.conf import settings

class TrafficMonitor:
    """网络流量监听与分析器，仅使用dumpcap抓包和ws-traffic-analyze-kit分析"""
    
    def __init__(self):
        # 配置路径（修改为指定的抓包目录）
        self.analyzer_path = Path(settings.WS_ANALYZER_PATH)
        self.pcap_dir = Path("network_trace_system/data/catched_data")  # 新的抓包存储目录
        self.ws_output_dir = Path(settings.WS_RESULT_SAVE_PATH)  # WS分析结果目录
        
        # 初始化目录
        self._init_directories()
        
        # 状态管理
        self.is_running = False
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._analysis_threads = []
        self.interface = self._detect_default_interface()
        
        # 配置参数
        self.capture_duration = settings.CAPTURE_DURATION  # 单次抓包时长
        self.max_analysis_threads = 5  # 最大分析线程数
        
    def _init_directories(self):
        """初始化抓包和分析结果目录"""
        self.pcap_dir.mkdir(exist_ok=True, parents=True)  # 确保目录存在
        self.ws_output_dir.mkdir(exist_ok=True, parents=True)
        
    def _detect_default_interface(self):
        """自动检测Windows默认网络接口"""
        try:
            import netifaces
            default_gateway = netifaces.gateways().get('default', {})
            if netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][1]
            
            # 列出所有可用接口
            interfaces = netifaces.interfaces()
            logging.info(f"可用网络接口: {interfaces}")  # 替换 logger
            if interfaces:
               return interfaces[0]
            
        except ImportError:
            logging.warning("未安装netifaces模块，请运行 'pip install netifaces' 安装")  # 替换 logger
        except Exception as e:
            logging.warning(f"自动检测接口失败: {e}")  # 替换 logger
        
        logging.warning("请手动配置网络接口，可用接口可通过 'dumpcap -D' 命令查看")  # 替换 logger
        return "Ethernet"  # 默认接口
    
    def start_monitoring(self, duration=None):
        """启动监听：抓包并触发WS分析"""
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
                logging.info(f"监听启动：接口={self.interface}，pcap存储={self.pcap_dir}")  # 替换 logger
                return {"status": "success", "message": "监控启动成功"}
            except Exception as e:
                self.is_running = False
                logging.error(f"启动失败: {e}")  # 替换 logger
                return {"status": "error", "message": str(e)}
    
    def stop_monitoring(self):
        """停止监听及分析线程"""
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
            logging.info("监控已停止")  # 替换 logger
            return {"status": "success", "message": "监控停止成功"}
    
    def _monitoring_loop(self, duration):
        """监听主循环：定时抓包并触发WS分析"""
        start_time = time.time()
        while self.is_running:
            if (time.time() - start_time) > duration:
                logging.info(f"达到监控时长{duration}秒，即将停止")  # 替换 logger
                break
            # 抓包
            capture_file = self._capture_traffic()
            if capture_file:
                # 异步执行WS分析
                self._start_analysis_thread(capture_file)
            time.sleep(1)
    
    def _capture_traffic(self):
        """使用dumpcap抓包并保存到指定目录"""
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
                logging.error(f"接口 {self.interface} 不存在，可用接口: {interfaces}")  # 替换 logger
                return None
                
            # 执行抓包命令（按配置时长抓包）
            cmd = [
                "dumpcap", "-i", self.interface, "-w", str(pcap_file),
                "-a", f"duration:{self.capture_duration}", "-q"
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding='utf-8',
                timeout=self.capture_duration + 5
            )
            
            if result.returncode != 0:
                logging.error(f"抓包命令错误输出: {result.stderr}")  # 替换 logger
                return None
                
            # 验证文件有效性
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                logging.info(f"抓包成功：{pcap_file}（大小：{pcap_file.stat().st_size}字节）")  # 替换 logger
                return pcap_file
            else:
                logging.warning(f"抓包文件为空，删除无效文件")  # 替换 logger
                if pcap_file.exists():
                    pcap_file.unlink()
                return None
                
        except FileNotFoundError:
            logging.error("未找到dumpcap程序，请确保Wireshark已安装并添加到系统PATH")  # 替换 logger
            return None
        except subprocess.TimeoutExpired:
            logging.error(f"抓包超时（超过{self.capture_duration + 5}秒）")  # 替换 logger
            return None
        except Exception as e:
            logging.error(f"抓包失败: {e}")  # 替换 logger
            return None
    
    def _start_analysis_thread(self, pcap_file):
        """启动WS分析线程（控制并发数）"""
        while len(self._analysis_threads) >= self.max_analysis_threads:
            self._analysis_threads = [t for t in self._analysis_threads if t.is_alive()]
            time.sleep(1)
        thread = threading.Thread(
            target=self._analyze_with_ws, args=(pcap_file,), daemon=True
        )
        thread.start()
        self._analysis_threads.append(thread)
    
    def _analyze_with_ws(self, pcap_file):
        """使用ws-traffic-analyze-kit分析pcap文件"""
        try:
            if not self.analyzer_path.exists():
                logging.error(f"WS分析工具路径不存在: {self.analyzer_path}")  # 替换 logger
                return
                
            # 构建WS分析命令
            output_file = self.ws_output_dir / f"ws_analysis_{pcap_file.stem}.json"
            cmd = [
                "cargo", "run",
                "--manifest-path", str(self.analyzer_path / "Cargo.toml"),
                "--",
                "-f", str(pcap_file),
                "-o", str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logging.info(f"WS流量分析完成: {pcap_file} -> 结果保存至 {output_file}")  # 替换 logger
            else:
                logging.error(f"WS流量分析失败: {result.stderr}")  # 替换 logger
                
        except Exception as e:
            logging.error(f"WS流量分析过程出错: {e}")  # 替换 logger