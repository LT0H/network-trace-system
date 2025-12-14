# 强制将src目录加入Python路径（建议根据实际环境调整路径）
import sys
import os
import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import traceback

# 关键：添加src目录的绝对路径（请根据实际部署环境修改）
SRC_DIR = r"C:\Users\z1395\network_trace_system\src"
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# 屏蔽Scapy的弃用警告
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 导入src目录下的模块
from active_probe import ActiveProbe
from elasticsearch_client import ESClient
from analyze_traffic import analyze_traffic_patterns, load_and_clean_data  # 补充导入
from cicflowmeter_utils import run_cicflowmeter

# 生产环境配置（建议生产环境使用配置文件管理）
SCAN_INTERVAL = 3600  # 扫描间隔（秒）- 1小时
TARGET_IPS = ["192.168.1.1", "8.8.8.8"]  # 监控目标IP列表
ES_HOSTS = ["http://localhost:9200"]  # Elasticsearch地址列表

class NetworkMonitorService(win32serviceutil.ServiceFramework):
    """
    Windows服务封装类：网络攻击溯源系统生产环境服务
    服务名称：NetworkMonitorService
    显示名称：Network Traffic Monitor Service
    """
    _svc_name_ = "NetworkMonitorService"
    _svc_display_name_ = "Network Traffic Monitor Service"
    _svc_description_ = "网络攻击溯源系统 - 流量监控与主动探测服务（生产环境）"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        self.es_client = None
        self.probe = ActiveProbe()
        try:
            # 项目根目录（建议根据实际环境修改）
            PROJECT_ROOT = r"C:\Users\z1395\network_trace_system"
            os.chdir(PROJECT_ROOT)  # 切换工作目录
            servicemanager.LogInfoMsg(f"已切换工作目录到：{PROJECT_ROOT}")
        except Exception as e:
            servicemanager.LogErrorMsg(f"切换工作目录失败：{str(e)}")


    def SvcDoRun(self):
        """服务运行核心逻辑 - 生产环境"""
        # 记录启动日志
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        
        try:
            self.is_running = True
            self._init_services()
            
            # 1. 初始化CICFlowMeter（生成最新CSV）
            servicemanager.LogInfoMsg("初始化CICFlowMeter，生成最新流量CSV...")
            try:
                run_cicflowmeter()
                servicemanager.LogInfoMsg("CICFlowMeter初始化完成")
            except Exception as e:
                servicemanager.LogErrorMsg(f"CICFlowMeter初始化失败：{str(e)}\n{traceback.format_exc()}")
                # 此处可根据需求决定是否终止服务或继续运行
                
            # 2. 后台循环执行监控任务
            while self.is_running:
                # 检查停止信号
                rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                
                # 2.1 执行主动探测
                servicemanager.LogInfoMsg("开始主动探测任务...")
                for ip in TARGET_IPS:
                    servicemanager.LogInfoMsg(f"扫描IP：{ip}")
                    try:
                        scan_result = self.probe.tcp_syn_scan(ip)
                        anomaly_result = self.probe.detect_anomaly_traffic(ip)
                        
                        if "error" in scan_result:
                            servicemanager.LogWarningMsg(f"IP {ip} 扫描错误：{scan_result['error']}")
                        else:
                            servicemanager.LogInfoMsg(f"IP {ip} 扫描完成，开放端口：{len(scan_result['open_ports'])}个")
                            
                        if "error" in anomaly_result:
                            servicemanager.LogWarningMsg(f"IP {ip} 异常检测错误：{anomaly_result['error']}")
                        else:
                            servicemanager.LogInfoMsg(f"IP {ip} 异常检测完成：{anomaly_result.get('status', '无结果')}")
                    except Exception as e:
                        servicemanager.LogErrorMsg(f"IP {ip} 探测失败：{str(e)}\n{traceback.format_exc()}")
                
                # 2.2 分析流量数据
                servicemanager.LogInfoMsg("开始流量数据分析...")
                try:
                    analysis_report = analyze_traffic_patterns()
                    if "error" in analysis_report:
                        servicemanager.LogWarningMsg(f"流量分析错误：{analysis_report['error']}")
                    else:
                        servicemanager.LogInfoMsg(
                            f"流量分析完成：总流量{analysis_report['total_flows']}条，"
                            f"恶意流量{analysis_report['malicious']['count']}条"
                        )
                        
                        # 2.3 将分析结果存入ES
                        if self.es_client:
                            try:
                                df = load_and_clean_data()
                                insert_result = self.es_client.bulk_insert(df)
                                servicemanager.LogInfoMsg(f"ES插入结果：{insert_result['message']}")
                            except Exception as e:
                                servicemanager.LogErrorMsg(f"ES数据插入失败：{str(e)}\n{traceback.format_exc()}")
                except Exception as e:
                    servicemanager.LogErrorMsg(f"流量分析失败：{str(e)}\n{traceback.format_exc()}")
                
                # 等待下一次循环
                time.sleep(SCAN_INTERVAL)
            
        except Exception as e:
            # 记录错误日志（含异常类型+详细堆栈）
            error_msg = f"服务运行崩溃：{type(e).__name__} - {str(e)}\n{traceback.format_exc()}"
            servicemanager.LogErrorMsg(error_msg)
            self.is_running = False
        finally:
            servicemanager.LogInfoMsg("服务主循环退出")

    def _init_services(self):
        """初始化依赖服务"""
        try:
            # 统一使用全局ES配置
            self.es_client = ESClient(hosts=ES_HOSTS)
            servicemanager.LogInfoMsg(f"ES客户端初始化成功，连接地址：{ES_HOSTS}")
        except Exception as e:
            servicemanager.LogWarningMsg(f"ES客户端初始化失败：{str(e)}\n{traceback.format_exc()}")
            self.es_client = None

    def SvcStop(self):
        """服务停止逻辑 - 生产环境"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "")
        )
        servicemanager.LogInfoMsg("网络监控服务已停止")

if __name__ == '__main__':
    """
    服务控制命令（需管理员权限）：
    install - 安装服务
    remove - 卸载服务
    start - 启动服务
    stop - 停止服务
    restart - 重启服务
    """
    win32serviceutil.HandleCommandLine(NetworkMonitorService)