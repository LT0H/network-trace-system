import os
import subprocess
import time
from pathlib import Path

# 配置路径（根据实际环境修改）
CICFLOWmeter_CSV_DIR = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\data\daily"
COMMON_IP_EXE_PATH = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\target\release\common_ip.exe"

def get_latest_csv(directory):
    """获取目录下最新的CSV文件"""
    csv_files = list(Path(directory).glob("*.csv"))
    if not csv_files:
        return None
    # 按修改时间排序，取最新的一个
    return max(csv_files, key=lambda f: f.stat().st_mtime)

def main():
    print("======================================================================")
    print("          CICFlowMeter 流量采集 + 枫叶数据集分析工具")
    print("======================================================================\n")

    # 步骤1：提示用户手动启动CICFlowMeter
    print("📌 步骤1：请手动启动CICFlowMeter采集流量")
    print(f"   启动命令：java -jar {os.path.join(r'C:\Users\z1395\network_trace_system\CICFlowMeter\target', 'CICFlowMeterV3-0.0.4-SNAPSHOT.jar')}")
    input("   采集完成后，按 Enter 键继续分析...\n")

    # 步骤2：检查CSV目录是否存在
    if not os.path.exists(CICFLOWmeter_CSV_DIR):
        print(f"❌ 错误：CSV目录不存在 - {CICFLOWmeter_CSV_DIR}")
        return

    # 步骤3：获取最新的CSV文件
    print("\n📌 步骤2：查找最新的流量CSV文件...")
    latest_csv = get_latest_csv(CICFLOWmeter_CSV_DIR)
    if not latest_csv:
        print(f"❌ 错误：在 {CICFLOWmeter_CSV_DIR} 中未找到CSV文件")
        return
    print(f"✅ 找到最新CSV文件：{latest_csv}")

    # 步骤4：调用枫叶分析工具（common_ip.exe）
    print("\n📌 步骤3：启动枫叶数据分析工具...")
    if not os.path.exists(COMMON_IP_EXE_PATH):
        print(f"❌ 错误：common_ip.exe不存在 - {COMMON_IP_EXE_PATH}")
        print("   请先编译ws-traffic-analyze-kit项目：cargo build --release")
        return

    try:
        # 调用Rust工具，传入CSV文件路径作为参数
        result = subprocess.run(
            [COMMON_IP_EXE_PATH, str(latest_csv)],
            capture_output=True,
            text=True,
            check=True
        )
        print("✅ 枫叶工具分析完成，结果已保存至 ip_counts.txt")

        # 打印分析结果
        print("\n📊 枫叶工具分析结果：")
        with open("ip_counts.txt", "r") as f:
            print(f.read())

    except subprocess.CalledProcessError as e:
        print(f"❌ 枫叶工具运行失败：{e.stderr}")
    except Exception as e:
        print(f"❌ 分析流程失败：{str(e)}")

if __name__ == "__main__":
    main()