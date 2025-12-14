import sys
import os
# 添加src目录到路径
SRC_DIR = r"C:\Users\z1395\network_trace_system\src"
sys.path.insert(0, SRC_DIR)

# 模拟服务初始化
try:
    from active_probe import ActiveProbe
    from elasticsearch_client import ESClient
    from analyze_traffic import analyze_traffic_patterns
    from cicflowmeter_utils import run_cicflowmeter

    # 1. 初始化ES客户端
    print("🔍 初始化ES客户端...")
    es_client = ESClient(hosts=["127.0.0.1:9200"])
    print("✅ ES客户端初始化成功")

    # 2. 初始化主动探测模块
    print("🔍 初始化主动探测模块...")
    probe = ActiveProbe()
    print("✅ 主动探测模块初始化成功")

    # 3. 测试CICFlowMeter路径
    print("🔍 检查CICFlowMeter JAR文件...")
    jar_path = r"C:\Users\z1395\network_trace_system\CICFlowMeter\target\CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
    if os.path.exists(jar_path):
        print("✅ CICFlowMeter JAR文件存在")
    else:
        print("❌ CICFlowMeter JAR文件不存在：", jar_path)

    # 4. 测试PCAP目录权限
    print("🔍 检查PCAP目录权限...")
    pcap_dir = r"C:\Users\z1395\network_trace_system\catched_data"
    os.makedirs(pcap_dir, exist_ok=True)
    test_file = os.path.join(pcap_dir, "test.txt")
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    print("✅ PCAP目录有读写权限")

    print("\n🎉 所有模块初始化成功，服务可正常运行！")
except Exception as e:
    print(f"\n❌ 服务初始化失败：{type(e).__name__} - {str(e)}")
    # 打印详细报错堆栈（定位具体哪一行出错）
    import traceback
    traceback.print_exc()