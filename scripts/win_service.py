# 强制将src目录加入Python路径（适配实际环境）
import sys
import os
import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import traceback
import logging

# 配置日志（生产环境输出到文件）
logging.basicConfig(
    filename=r"C:\Users\z1395\network_trace_system\logs\service.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# 添加src目录路径
SRC_DIR = r"C:\Users\z1395\network_trace_system\src"
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# 屏蔽Scapy弃用警告
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 导入核心模块
from active_probe import ActiveProbe
from elasticsearch_client import ESClient
from analyze_traffic import analyze_traffic_patterns, load_and_clean_data
from cicflowmeter_utils import run_cicflowmeter

# 生产环境配置（无自动运行逻辑）
SCAN_INTERVAL = 3600  # 扫描间隔（秒）
TARGET_IPS = []  # 禁用自动扫描（需手动触发）
ES_HOSTS = ["localhost:9200"]  # 修正ES连接地址

class NetworkMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkMonitorService"
    _svc_display_name_ = "Network Traffic Monitor Service"
    _svc_description_ = "网络攻击溯源系统 - 流量监控与主动探测服务"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        self.es_client = None
        self.probe = ActiveProbe()
        self._init_workdir()

    def _init_workdir(self):
        """初始化工作目录"""
        try:
            PROJECT_ROOT = r"C:\Users\z1395\network_trace_system"
            os.makedirs(PROJECT_ROOT, exist_ok=True)
            os.chdir(PROJECT_ROOT)
            logging.info(f"工作目录切换至：{PROJECT_ROOT}")
        except Exception as e:
            error_msg = f"工作目录初始化失败：{str(e)}"
            logging.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)

    def SvcDoRun(self):
        """服务运行逻辑（生产环境）"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        logging.info("服务启动成功")

        try:
            self.is_running = True
            self._init_services()

            # 初始化CICFlowMeter（仅执行一次）
            self._init_cicflowmeter()

            # 后台循环（等待手动触发任务，无自动扫描）
            while self.is_running:
                rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                time.sleep(1)

        except Exception as e:
            error_msg = f"服务运行错误：{type(e).__name__} - {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)
        finally:
            logging.info("服务停止")

    def _init_services(self):
        """初始化依赖服务（ES）"""
        try:
            self.es_client = ESClient(hosts=ES_HOSTS)
            logging.info("ES客户端初始化成功")
        except Exception as e:
            error_msg = f"ES客户端初始化失败：{str(e)}"
            logging.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)
            self.es_client = None

    def _init_cicflowmeter(self):
        """初始化CICFlowMeter（生成流量数据）"""
        try:
            logging.info("开始初始化CICFlowMeter...")
            run_cicflowmeter()
            logging.info("CICFlowMeter初始化完成")
        except Exception as e:
            error_msg = f"CICFlowMeter初始化失败：{str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)

    def SvcStop(self):
        """服务停止逻辑"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "")
        )
        logging.info("服务已停止")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(NetworkMonitorService)