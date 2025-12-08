import os
import subprocess
import time
from pathlib import Path

# ========== 核心路径配置（全绝对路径） ==========
# CICFlowMeter 相关
CICFLOWMETER_JAR = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
CICFLOWMETER_OUTPUT_DIR = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\data\daily"
# 枫叶分析工具相关
COMMON_IP_EXE = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\target\release\common_ip.exe"
RESULT_FILE_PATH = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\ip_counts.txt"

def get_latest_csv(directory):
    """获取目录下最新的CSV文件"""
    os.makedirs(directory, exist_ok=True)  # 确保目录存在
    csv_files = list(Path(directory).glob("*.csv"))
    if not csv_files:
        return None
    return max(csv_files, key=lambda f: f.stat().st_mtime)

def main():
    print("======================================================================")
    print("          CICFlowMeter 流量采集 + 枫叶数据集分析工具")
    print("======================================================================\n")

    # 步骤1：提示用户启动CICFlowMeter（指定输出目录）
    print("📌 步骤1：请复制以下命令启动CICFlowMeter（强制指定输出目录）：")
    # 关键：给CICFlowMeter指定输出目录参数（适配其参数格式）
    cic_cmd = f"java -jar \"{CICFLOWMETER_JAR}\" -o \"{CICFLOWMETER_OUTPUT_DIR}\""
    print(f"   {cic_cmd}")
    input("   采集完成后关闭CICFlowMeter，按 Enter 键继续分析...\n")

    # 步骤2：检查并获取最新CSV
    print("\n📌 步骤2：查找最新的流量CSV文件...")
    latest_csv = get_latest_csv(CICFLOWMETER_OUTPUT_DIR)
    if not latest_csv:
        print(f"❌ 错误：在 {CICFLOWMETER_OUTPUT_DIR} 中未找到CSV文件")
        print("💡 请确认CICFlowMeter是否正常生成CSV，或输出目录是否正确")
        return
    print(f"✅ 找到最新CSV文件：{latest_csv}")

    # 步骤3：调用枫叶分析工具（强制切换工作目录 + 指定编码）
    print("\n📌 步骤3：启动枫叶数据分析工具...")
    if not os.path.exists(COMMON_IP_EXE):
        print(f"❌ 错误：common_ip.exe不存在 - {COMMON_IP_EXE}")
        print("   请先编译：cd C:\\Users\\z1395\\network_trace_system\\ws-traffic-analyze-kit && cargo build --release")
        return

    try:
        # 关键：切换到exe所在目录运行，避免路径依赖问题
        exe_work_dir = os.path.dirname(COMMON_IP_EXE)
        result = subprocess.run(
            [COMMON_IP_EXE, str(latest_csv)],
            cwd=exe_work_dir,  # 切换工作目录
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            check=True,
            timeout=300  # 超时5分钟
        )
        print("✅ 枫叶工具分析完成！")
        print(f"🔍 工具输出：{result.stdout.strip()}")

        # 步骤4：读取并打印结果
        print("\n📊 枫叶工具分析结果：")
        if os.path.exists(RESULT_FILE_PATH):
            with open(RESULT_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if content:
                    print(content)
                else:
                    print("⚠️  警告：ip_counts.txt文件为空（可能CSV无有效数据）")
        else:
            print(f"❌ 错误：未找到结果文件 - {RESULT_FILE_PATH}")
            print("💡 请检查common_ip.exe是否正常运行，或Rust代码中输出路径是否正确")

    except subprocess.TimeoutExpired:
        print("❌ 错误：枫叶工具运行超时（5分钟）")
    except subprocess.CalledProcessError as e:
        print(f"❌ 枫叶工具运行失败（退出码：{e.returncode}）")
        print(f"🔍 错误输出：{e.stderr.strip()}")
    except Exception as e:
        print(f"❌ 分析流程失败：{str(e)}")

if __name__ == "__main__":
    main()