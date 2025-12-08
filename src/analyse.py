import subprocess
import os
import sys
import signal
import psutil  # 需安装：pip install psutil

# ===================== 固定绝对路径（核心）=====================
# 根目录
NETWORK_TRACE_ROOT = r"C:\Users\z1395\network_trace_system"
# CICFlowMeter相关路径
CICFLOWMETER_JAR = os.path.join(NETWORK_TRACE_ROOT, "CICFlowMeter", "target", "CICFlowMeterV3-0.0.4-SNAPSHOT.jar")
JNETPCAP_DLL_DIR = os.path.join(NETWORK_TRACE_ROOT, "CICFlowMeter", "jnetpcap", "win", "jnetpcap-1.4.r1425")
CSV_OUTPUT_DIR = os.path.join(NETWORK_TRACE_ROOT, "CICFlowMeter", "target", "data", "daily")

# 全局进程对象
cic_process = None

def check_file_exists(path, desc):
    """检查文件/目录是否存在"""
    if not os.path.exists(path):
        print(f"❌ 错误：{desc} 不存在\n路径：{path}")
        sys.exit(1)
    print(f"✅ 验证通过：{desc}")

def start_cicflowmeter():
    """启动CICFlowMeter JAR包（模拟双击运行）"""
    global cic_process
    # 前置检查
    check_file_exists(CICFLOWMETER_JAR, "CICFlowMeter JAR包")
    check_file_exists(JNETPCAP_DLL_DIR, "jnetpcap原生库目录")
    # 创建CSV目录（不存在则自动创建）
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    # 构造Java启动命令（指定原生库+JAR包）
    java_cmd = [
        "java",
        f"-Djava.library.path={JNETPCAP_DLL_DIR}",
        "-jar", CICFLOWMETER_JAR,
        "-o", CSV_OUTPUT_DIR  # 若JAR支持指定输出目录，无则删除该行
    ]

    try:
        # 启动JAR（非阻塞，后台运行）
        cic_process = subprocess.Popen(
            java_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP  # Windows下支持信号终止
        )
        print(f"\n🚀 CICFlowMeter已启动（PID：{cic_process.pid}）")
        print(f"📂 CSV输出目录：{CSV_OUTPUT_DIR}")
        
        # 实时打印JAR输出日志（可选）
        # for line in iter(cic_process.stdout.readline, ""):
        #     if line:
        #         print(f"[CICFlowMeter] {line.strip()}")

    except Exception as e:
        print(f"\n❌ 启动CICFlowMeter失败：{str(e)}")
        sys.exit(1)

def stop_cicflowmeter():
    """停止CICFlowMeter进程（强制终止关联Java进程）"""
    global cic_process
    # 方式1：终止直接启动的进程
    if cic_process and cic_process.poll() is None:
        try:
            # Windows下终止进程组
            os.kill(cic_process.pid, signal.CTRL_BREAK_EVENT)
            cic_process.wait(timeout=3)
            print(f"\n🛑 CICFlowMeter进程已停止（PID：{cic_process.pid}）")
        except:
            # 方式2：兜底-杀死所有关联的Java进程（谨慎使用）
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'java.exe' and CICFLOWMETER_JAR in ' '.join(proc.info['cmdline']):
                        proc.kill()
                        print(f"\n🛑 强制终止CICFlowMeter关联进程（PID：{proc.info['pid']}）")
                except:
                    pass
    else:
        print("\nℹ️  CICFlowMeter未运行")

if __name__ == "__main__":
    try:
        start_cicflowmeter()
        input("\n按Enter键停止CICFlowMeter...\n")
    finally:
        stop_cicflowmeter()