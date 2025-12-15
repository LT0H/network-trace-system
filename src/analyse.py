import subprocess
import os
import sys
import signal
import psutil
import ctypes  # 提前导入ctypes，避免函数内引用问题
import argparse  # 新增：用于命令行参数解析


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


def check_dir_writable(directory, desc):
    """检查目录是否可写（新增：避免后续写入失败）"""
    try:
        # 创建临时测试文件
        test_file = os.path.join(directory, f"test_write_{os.getpid()}.tmp")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("test")
        os.remove(test_file)
        print(f"✅ 验证通过：{desc} 目录可写")
        return True
    except PermissionError:
        print(f"❌ 错误：{desc} 目录无写入权限\n路径：{directory}")
        print("💡 解决方案：以管理员身份运行本脚本")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 错误：检查{desc}目录可写性失败\n原因：{str(e)}")
        sys.exit(1)


def check_admin():
    """检查是否拥有管理员权限（优化：提前导入ctypes，修复引用问题）"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"⚠️ 警告：检查管理员权限时出错：{str(e)}")
        return False


def start_cicflowmeter(debug=False):
    """启动CICFlowMeter JAR包（新增：debug参数控制日志输出）"""
    global cic_process
    # 前置检查（增强：增加目录可写性验证）
    check_file_exists(CICFLOWMETER_JAR, "CICFlowMeter JAR包")
    check_file_exists(JNETPCAP_DLL_DIR, "jnetpcap原生库目录")
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    check_dir_writable(CSV_OUTPUT_DIR, "CSV输出")

    # 构造Java启动命令
    java_cmd = [
        "java",
        f"-Djava.library.path={JNETPCAP_DLL_DIR}",
        "-Dfile.encoding=UTF-8",  # 解决中文乱码
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
        
        # 实时打印JAR输出日志（根据debug参数控制）
        if debug:
            print("\n📝 启用调试日志输出（CICFlowMeter运行日志）：")
            def log_monitor():
                """日志监控线程函数"""
                for line in iter(cic_process.stdout.readline, ""):
                    if line:
                        print(f"[CICFlowMeter] {line.strip()}")
            # 启动日志监控线程（避免阻塞主线程）
            import threading
            log_thread = threading.Thread(target=log_monitor, daemon=True)
            log_thread.start()

    except Exception as e:
        print(f"\n❌ 启动CICFlowMeter失败：{str(e)}")
        print(f"💡 解决方案：")
        print(f"   1. 以管理员身份运行本脚本")
        print(f"   2. 确保已安装Java 8+（JDK/JRE）并配置环境变量")
        print(f"   3. 确保jnetpcap.dll在系统路径中（{JNETPCAP_DLL_DIR}）")
        sys.exit(1)


def stop_cicflowmeter():
    """停止CICFlowMeter进程（优化：细化异常处理）"""
    global cic_process
    # 方式1：终止直接启动的进程
    if cic_process and cic_process.poll() is None:
        try:
            # Windows下终止进程组
            os.kill(cic_process.pid, signal.CTRL_BREAK_EVENT)
            # 等待进程终止（最多等待5秒）
            try:
                cic_process.wait(timeout=5)
                print(f"\n🛑 CICFlowMeter进程已正常停止（PID：{cic_process.pid}）")
            except subprocess.TimeoutExpired:
                print(f"\n⚠️ CICFlowMeter进程终止超时，尝试强制终止...")
                cic_process.kill()
                print(f"🛑 CICFlowMeter进程已强制停止（PID：{cic_process.pid}）")
        except Exception as e:
            print(f"\n⚠️ 终止主进程失败：{str(e)}，尝试清理关联进程...")
            # 方式2：兜底-杀死所有关联的Java进程
            killed = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] == 'java.exe' and CICFLOWMETER_JAR in ' '.join(proc.info['cmdline']):
                        proc.kill()
                        print(f"🛑 强制终止CICFlowMeter关联进程（PID：{proc.info['pid']}）")
                        killed = True
                except Exception as sub_e:
                    print(f"⚠️ 清理进程时出错：{str(sub_e)}")
            if not killed:
                print("ℹ️ 未找到需要清理的关联进程")
    else:
        print("\nℹ️ CICFlowMeter未运行或已停止")


def main():
    # 解析命令行参数（新增：支持--debug启用日志）
    parser = argparse.ArgumentParser(description="启动和停止CICFlowMeter流量分析工具")
    parser.add_argument("--debug", action="store_true", help="启用CICFlowMeter调试日志输出")
    args = parser.parse_args()

    # 管理员权限检查
    if not check_admin():
        print("⚠️ 警告：未以管理员身份运行，可能导致抓包失败或权限不足！")
        user_input = input("是否继续？(y/N)：").strip().lower()
        if user_input != 'y':
            print("程序已退出，请以管理员身份重新运行")
            sys.exit(0)
    
    try:
        start_cicflowmeter(debug=args.debug)
        input("\n按Enter键停止CICFlowMeter...\n")
    finally:
        stop_cicflowmeter()


if __name__ == "__main__":
    main()