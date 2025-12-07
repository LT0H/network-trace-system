import logging
import sys
import time
from scanner.task_manager import TaskManager
from scanner.topology import NetworkTopology
from django.conf import settings

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("traffic_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def main():
    logger.info("网络流量监控系统启动")
    
    # 初始化任务管理器
    task_manager = TaskManager()
    
    # 简单的命令行交互
    while True:
        print("\n网络流量监控系统")
        print("1. 创建扫描任务")
        print("2. 启动任务")
        print("3. 停止任务")
        print("4. 查看任务状态")
        print("5. 列出所有任务")
        print("6. 查看任务结果")
        print("7. 退出")
        
        choice = input("请选择操作: ")
        
        if choice == "1":
            target = input("请输入目标IP或域名: ")
            duration = int(input("请输入扫描时长(秒，默认3600): ") or 3600)
            interval = int(input("请输入扫描间隔(秒，默认60): ") or 60)
            task_id = task_manager.create_task(target, duration, interval)
            print(f"任务创建成功，ID: {task_id}")
            
        elif choice == "2":
            task_id = input("请输入任务ID: ")
            result = task_manager.start_task(task_id)
            print(result["message"])
            
        elif choice == "3":
            task_id = input("请输入任务ID: ")
            result = task_manager.stop_task(task_id)
            print(result["message"])
            
        elif choice == "4":
            task_id = input("请输入任务ID: ")
            status = task_manager.get_task_status(task_id)
            print(json.dumps(status, indent=2, ensure_ascii=False))
            
        elif choice == "5":
            tasks = task_manager.list_tasks()
            print(json.dumps(tasks, indent=2, ensure_ascii=False))
            
        elif choice == "6":
            task_id = input("请输入任务ID: ")
            results = task_manager.get_task_results(task_id)
            
            # 生成拓扑图
            topology_generator = NetworkTopology()
            for result in results.get("results", []):
                if "data" in result:
                    topology_generator.add_flow_data(result["data"])
            
            topology_image = topology_generator.generate_topology_image(task_id)
            results["topology_image"] = topology_image
            
            print(json.dumps(results, indent=2, ensure_ascii=False))
            
        elif choice == "7":
            print("系统退出")
            break
            
        else:
            print("无效的选择，请重试")

if __name__ == "__main__":
    main()