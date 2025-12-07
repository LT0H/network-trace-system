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
    """网络流量监听与分析器，使用dumpcap抓包和ws-traffic-analyze-kit分析"""
    
    def __init__(self):
        # 路径配置
        self.pcap_dir = Path(settings.PCAP_SAVE_PATH)
        self.analysis_result_dir = Path(settings.ANALYSIS_RESULT_PATH)
        self.ws_analyzer_path = Path(settings.WS_ANALYZER_PATH)
        
        # 状态管理
        self.is_running = False
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._analysis_threads = []
        self.interface = self._detect_default_interface()
        
        # 配置参数
        self.capture_duration = settings.CAPTURE_DURATION
        self.max_analysis_threads = settings.MAX_ANALYSIS_THREADS
        
    def _detect_default_interface(self):
        """自动检测Windows默认网络接口"""
        try:
            # 使用netifaces检测
            import netifaces
            default_gateway = netifaces.gateways().get('default', {})
            if netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][1]
            
            # 列出所有可用接口
            interfaces = netifaces.interfaces()
            logger.info(f"可用网络接口: {interfaces}")
            if interfaces:
               return interfaces[0]
            
        except ImportError:
            logger.warning("未安装netifaces模块，请运行 'pip install netifaces' 安装")
        except Exception as e:
            logger.warning(f"自动检测接口失败: {e}")
        
        logger.warning("使用默认网络接口")
        return settings.DEFAULT_INTERFACE
    
    def start_monitoring(self, duration=None, target=None):
        """启动监听：抓pcap并分析"""
        with self._lock:
            if self.is_running:
                return {"status": "warning", "message": "监控已运行"}
            try:
                self.is_running = True
                self._monitor_thread = threading.Thread(
                    target=self._monitoring_loop, 
                    args=(duration or 3600, target),  # 默认1小时
                    daemon=True
                )
                self._monitor_thread.start()
                logger.info(f"监听启动：接口={self.interface}，pcap存储={self.pcap_dir}")
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
            if self._monitor_thread:
                self._monitor_thread.join(timeout=10)
                self._monitor_thread = None
            # 等待分析线程结束
            for thread in self._analysis_threads:
                thread.join(timeout=5)
            self._analysis_threads.clear()
            logger.info("监控已停止")
            return {"status": "success", "message": "监控停止成功"}
    
    def _monitoring_loop(self, duration, target=None):
        """监听主循环：定时抓包+触发分析"""
        start_time = time.time()
        while self.is_running:
            if (time.time() - start_time) > duration:
                logger.info(f"达到监控时长{duration}秒，即将停止")
                break
                
            # 抓pcap文件
            capture_file = self._capture_traffic(target)
            if capture_file:
                # 异步分析
                self._start_analysis_thread(capture_file)
            
            time.sleep(1)
    
    def _capture_traffic(self, target=None):
        """用dumpcap抓包，存到指定目录"""
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
                
            # 构建dumpcap命令
            cmd = [
                "dumpcap", "-i", self.interface, "-w", str(pcap_file),
                "-a", f"duration:{self.capture_duration}", "-q"
            ]
            
            # 如果指定了目标，添加过滤条件
            if target:
                # 支持IP或域名
                cmd.extend(["-f", f"host {target}"])
                
            # 执行抓包命令
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding='utf-8',
                timeout=self.capture_duration + 5
            )
            
            if result.returncode != 0:
                logger.error(f"抓包命令错误输出: {result.stderr}")
                return None
                
            # 验证文件有效
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
        """启动线程进行分析，控制并发数"""
        # 清理已完成的线程
        self._analysis_threads = [t for t in self._analysis_threads if t.is_alive()]
        
        # 控制最大并发数
        while len(self._analysis_threads) >= self.max_analysis_threads:
            time.sleep(1)
            self._analysis_threads = [t for t in self._analysis_threads if t.is_alive()]
            
        thread = threading.Thread(
            target=self._analyze_with_ws, args=(pcap_file,), daemon=True
        )
        thread.start()
        self._analysis_threads.append(thread)
    
    def _analyze_with_ws(self, pcap_file):
        """使用ws-traffic-analyze-kit分析pcap文件"""
        try:
            if not self.ws_analyzer_path.exists():
                logger.error(f"WS分析工具不存在: {self.ws_analyzer_path}")
                return
                
            # 构建输出文件名
            output_file = self.analysis_result_dir / f"analysis_{pcap_file.stem}.json"
            
            # 执行分析命令
            cmd = [
                str(self.ws_analyzer_path),
                "-f", str(pcap_file),
                "-o", str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"WS流量分析完成: {pcap_file} -> {output_file}")
                # 可以在这里将结果存入数据库
                return output_file
            else:
                logger.error(f"WS流量分析失败: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"WS流量分析过程出错: {e}")
            return None