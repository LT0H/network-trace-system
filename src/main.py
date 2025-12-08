import os
import sys
import time
import threading
import use_CICFlowMeter
import analyse

def main():
    """主流程：启动CICFlowMeter → 停止 → 分析CSV"""
    print("=" * 70)
    print("          CICFlowMeter 流量采集 + 枫叶数据集分析工具")
    print("=" * 70)

    # 1. 启动CICFlowMeter（后台线程）
    print("\n📌 步骤1：启动CICFlowMeter流量采集...")
    try:
        cic_thread = threading.Thread(target=use_CICFlowMeter.start_cicflowmeter)
        cic_thread.daemon = True
        cic_thread.start()
        print("✅ CICFlowMeter采集线程已启动")
    except Exception as e:
        print(f"❌ 启动采集失败：{str(e)}")
        sys.exit(1)

    # 2. 等待用户停止指令
    print("\n📌 步骤2：采集已开始，按 Enter 键停止采集并分析CSV...")
    try:
        input()  # 阻塞等待用户输入
    except KeyboardInterrupt:
        print("\n⚠️  接收到中断信号，准备停止采集...")

    # 3. 停止CICFlowMeter
    print("\n📌 步骤3：停止CICFlowMeter采集...")
    use_CICFlowMeter.stop_cicflowmeter()
    time.sleep(2)  # 等待CSV文件写入完成

    # 4. 分析CSV文件
    print("\n📌 步骤4：启动枫叶数据分析工具...")
    try:
        analyse.analyse_csv()
    except Exception as e:
        print(f"\n❌ 分析流程失败：{str(e)}")
        sys.exit(1)

    # 5. 结束
    print("\n" + "=" * 70)
    print("          所有流程执行完成！")
    print("=" * 70)

if __name__ == "__main__":
    # 检查Python版本
    if sys.version_info < (3, 7):
        print("❌ 要求Python 3.7及以上版本")
        sys.exit(1)
    # 检查依赖
    try:
        import psutil
    except ImportError:
        print("❌ 缺少依赖psutil，请执行：pip install psutil")
        sys.exit(1)
    # 启动主流程
    try:
        main()
    except Exception as e:
        print(f"\n❌ 主程序异常退出：{str(e)}")
        sys.exit(1)