"""网络追踪系统主程序"""
import sys
import time
from pathlib import Path
from task_manager import TaskManager, NetworkTask, AnalysisTask, UpdateTask
from attack_signatures.update_signatures import SignatureManager

# 添加项目根目录到模块路径（确保跨平台兼容）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

def check_dependencies():
    """检查所有依赖"""
    print("\n🔍 检查依赖项...")
    
    dependencies = {
        "WinPcap/Npcap": check_npcap_winpcap(),
        "Java": check_java(),
        "CICFlowMeter JAR": check_cicflowmeter_jar(),
        "Wireshark": check_wireshark(),
        "pcap2para": check_pcap2para(),
        "任务管理器组件": True  # 内置模块，默认可用
    }
    
    all_ok = True
    for dep, status in dependencies.items():
        if status:
            print(f"✅ {dep}: 已安装")
        else:
            print(f"❌ {dep}: 未找到")
            all_ok = False
    
    return all_ok

# 依赖检查实现（保持原有逻辑）
def check_npcap_winpcap():
    try:
        import pcapy  # 依赖WinPcap/Npcap的Python绑定
        return True
    except ImportError:
        return False

def check_java():
    try:
        import subprocess
        subprocess.run(["java", "-version"], check=True, capture_output=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def check_cicflowmeter_jar():
    cicflow_path = PROJECT_ROOT / "tools" / "CICFlowMeter-4.0.jar"
    return cicflow_path.exists()

def check_wireshark():
    try:
        import subprocess
        subprocess.run(["tshark", "--version"], check=True, capture_output=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def check_pcap2para():
    # 检查pcap转换工具
    pcap2para_path = PROJECT_ROOT / "tools" / "pcap2para"
    return pcap2para_path.exists() and pcap2para_path.is_file()

def main():
    """主程序入口"""
    print("🚀 网络追踪系统启动中...")
    
    # 检查依赖
    if not check_dependencies():
        print("\n❌ 缺少必要依赖，程序无法启动")
        sys.exit(1)
    
    # 初始化核心组件
    try:
        signature_manager = SignatureManager()
        task_manager = TaskManager(max_workers=3)
        task_manager.start()
        print("\n✅ 核心组件初始化完成")
    except Exception as e:
        print(f"\n❌ 核心组件初始化失败：{str(e)}")
        sys.exit(1)
    
    # 演示任务调度（实际使用时可根据需求调整）
    try:
        print("\n📋 调度演示任务...")
        
        # 1. 创建特征库更新任务
        update_task = UpdateTask(update_source="remote")
        update_task_id = task_manager.add_task(update_task)
        
        # 2. 等待更新完成（最多30秒）
        for _ in range(30):
            task = task_manager.get_task_status(update_task_id)
            if task.status in [task.status.COMPLETED, task.status.FAILED]:
                break
            time.sleep(1)
        
        # 3. 创建网络监控任务
        monitor_task = NetworkTask(interface="eth0", duration=60)
        monitor_task_id = task_manager.add_task(monitor_task)
        
        # 4. 创建分析任务
        analysis_task = AnalysisTask(input_file="/tmp/sample.pcap")
        analysis_task_id = task_manager.add_task(analysis_task)
        
        # 显示任务状态
        print("\n当前任务状态：")
        for task in task_manager.list_tasks():
            print(f"- {task.task_name} [{task.status.value}] 进度：{task.progress}%")
        
        # 保持程序运行（实际环境可根据需要调整）
        print("\n⏳ 系统运行中... (按Ctrl+C退出)")
        while True:
            time.sleep(3600)  # 持续运行
            
    except KeyboardInterrupt:
        print("\n👋 用户中断，程序退出")
    except Exception as e:
        print(f"\n❌ 程序运行异常：{str(e)}")
    finally:
        # 清理资源
        task_manager.stop()
        print("\n🔌 系统已关闭")

if __name__ == "__main__":
    main()