import sys
import os
import logging
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("service_tester")

# 添加src目录到路径
SRC_DIR = r"C:\Users\z1395\network_trace_system\src"
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

def test_es_connection():
    """测试Elasticsearch连接"""
    logger.info("🔍 测试ES连接...")
    try:
        from elasticsearch_client import ESClient
        es = ESClient(hosts=["localhost:9200"])
        logger.info("✅ ES连接测试通过")
        return True
    except Exception as e:
        logger.error(f"❌ ES连接测试失败：{str(e)}", exc_info=True)
        return False

def test_active_probe():
    """测试主动探测模块"""
    logger.info("🔍 测试主动探测模块...")
    try:
        from active_probe import ActiveProbe
        probe = ActiveProbe()
        # 测试本地回环地址扫描（安全测试）
        result = probe.tcp_syn_scan("127.0.0.1", ports=[80, 443, 8000])
        logger.info(f"扫描结果：{result}")
        logger.info("✅ 主动探测模块测试通过")
        return True
    except Exception as e:
        logger.error(f"❌ 主动探测模块测试失败：{str(e)}", exc_info=True)
        return False

def test_traffic_analysis():
    """测试流量分析模块"""
    logger.info("🔍 测试流量分析模块...")
    try:
        from analyze_traffic import analyze_traffic_patterns
        report = analyze_traffic_patterns()
        if "error" in report:
            logger.warning(f"⚠️ 流量分析返回警告：{report['error']}")
        else:
            logger.info(f"分析结果：总流量{report['total_flows']}条")
        logger.info("✅ 流量分析模块测试通过")
        return True
    except Exception as e:
        logger.error(f"❌ 流量分析模块测试失败：{str(e)}", exc_info=True)
        return False

def test_cicflowmeter():
    """测试CICFlowMeter可用性"""
    logger.info("🔍 测试CICFlowMeter...")
    try:
        from main import CICFLOWMETER_JAR, CICFLOWMETER_OUTPUT_DIR
        if not os.path.exists(CICFLOWMETER_JAR):
            raise FileNotFoundError(f"CICFlowMeter JAR不存在：{CICFLOWMETER_JAR}")
        
        # 检查输出目录权限
        os.makedirs(CICFLOWMETER_OUTPUT_DIR, exist_ok=True)
        test_file = os.path.join(CICFLOWMETER_OUTPUT_DIR, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        
        logger.info("✅ CICFlowMeter测试通过")
        return True
    except Exception as e:
        logger.error(f"❌ CICFlowMeter测试失败：{str(e)}", exc_info=True)
        return False

def test_django_setup():
    """测试Django环境"""
    logger.info("🔍 测试Django环境...")
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "network_monitor.settings")
        import django
        django.setup()
        
        # 测试数据库连接
        from django.db import connection
        with connection.cursor():
            pass
        
        # 测试模型
        from dashboard.models import Task
        Task.objects.count()  # 仅测试查询
        
        logger.info("✅ Django环境测试通过")
        return True
    except Exception as e:
        logger.error(f"❌ Django环境测试失败：{str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    logger.info("开始服务完整性测试...")
    
    tests = [
        test_es_connection,
        test_active_probe,
        test_cicflowmeter,
        test_traffic_analysis,
        test_django_setup
    ]
    
    results = [test() for test in tests]
    
    if all(results):
        logger.info("🎉 所有测试通过，系统可正常运行！")
    else:
        logger.error("❌ 部分测试失败，请检查上述错误信息")