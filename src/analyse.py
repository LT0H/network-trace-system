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

def check_admin():
    """新增：检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_cicflowmeter():
    """启动CICFlowMeter JAR包（修复：去掉不支持的-o参数）"""
    global cic_process
    # 前置检查
    check_file_exists(CICFLOWMETER_JAR, "CICFlowMeter JAR包")
    check_file_exists(JNETPCAP_DLL_DIR, "jnetpcap原生库目录")
    # 创建CSV目录（不存在则自动创建）
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    # 构造Java启动命令（核心修复：去掉-o参数，GUI版不支持）
    java_cmd = [
        "java",
        f"-Djava.library.path={JNETPCAP_DLL_DIR}",
        "-Dfile.encoding=UTF-8",  # 新增：解决中文乱码
        "-jar", CICFLOWMETER_JAR
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
        print(f"📂 请在CICFlowMeter GUI中手动设置CSV输出目录：{CSV_OUTPUT_DIR}")
        print(f"📋 操作步骤：")
        print(f"   1. 打开CICFlowMeter窗口后，点击'Output Directory'")
        print(f"   2. 选择目录：{CSV_OUTPUT_DIR}")
        print(f"   3. 选择正确的网卡，点击Start开始抓包")
        print(f"   4. 访问http://www.baidu.com（HTTP）生成流量")
        
        # 实时打印JAR输出日志（调试用）
        # for line in iter(cic_process.stdout.readline, ""):
        #     if line:
        #         print(f"[CICFlowMeter] {line.strip()}")

    except Exception as e:
        print(f"\n❌ 启动CICFlowMeter失败：{str(e)}")
        print(f"💡 解决方案：")
        print(f"   1. 以管理员身份运行本脚本")
        print(f"   2. 确保已安装Java 8+（JDK/JRE）")
        print(f"   3. 确保jnetpcap.dll在系统路径中")
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
    # 新增：管理员权限检查
    try:
        import ctypes
        if not check_admin():
            print("⚠️ 警告：未以管理员身份运行，可能导致抓包失败！")
            input("\n按Enter继续（建议退出并以管理员身份运行）...\n")
    except:
        pass
    
    try:
        start_cicflowmeter()
        input("\n按Enter键停止CICFlowMeter...\n")
    finally:
        stop_cicflowmeter()