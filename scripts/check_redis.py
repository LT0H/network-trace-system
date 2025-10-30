#!/usr/bin/env python
"""
Redis连接检查脚本 - 最终修复版本
"""
import os
import sys
import redis

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def check_redis_basic():
    """基础Redis连接检查"""
    print("1. 基础Redis连接检查:")
    redis_urls = [
        ('任务队列', 'redis://localhost:6379/0'),
        ('缓存', 'redis://localhost:6379/1')
    ]
    
    all_success = True
    
    for name, url in redis_urls:
        try:
            print(f"   测试 {name} ({url})...", end=' ')
            r = redis.Redis.from_url(url, socket_connect_timeout=3)
            r.ping()
            print("✅ 成功")
        except redis.ConnectionError:
            print("❌ 失败 - 连接被拒绝")
            all_success = False
        except Exception as e:
            print(f"❌ 错误 - {e}")
            all_success = False
    
    return all_success

def check_redis_with_django_simple():
    """简化版Django配置检查"""
    print("\n2. Django配置检查:")
    try:
        # 设置最简单的Django环境
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trace_system.settings')
        
        import django
        from django.conf import settings
        
        django.setup()
        
        print("   ✅ Django设置加载成功")
        
        # 检查配置
        if hasattr(settings, 'CELERY_BROKER_URL'):
            print(f"   ✅ Celery Broker: {settings.CELERY_BROKER_URL}")
        else:
            print("   ⚠️  未找到CELERY_BROKER_URL配置")
            
        if hasattr(settings, 'CACHES') and 'default' in settings.CACHES:
            cache_backend = settings.CACHES['default'].get('BACKEND', '')
            print(f"   ✅ 缓存后端: {cache_backend}")
        else:
            print("   ⚠️  未找到缓存配置")
            
        return True
        
    except Exception as e:
        print(f"   ❌ Django配置检查失败: {e}")
        return False

def check_celery_connection():
    """检查Celery连接"""
    print("\n3. Celery连接测试:")
    try:
        from celery import current_app
        
        # 测试Celery连接
        insp = current_app.control.inspect()
        stats = insp.stats()
        
        if stats:
            print("   ✅ Celery连接正常")
            for node, info in stats.items():
                print(f"     节点: {node}")
        else:
            print("   ⚠️  没有活动的Celery Worker")
            
        return True
        
    except Exception as e:
        print(f"   ❌ Celery连接测试失败: {e}")
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Redis和Celery连接检查")
    print("=" * 50)
    
    # 执行检查
    redis_ok = check_redis_basic()
    django_ok = check_redis_with_django_simple()
    celery_ok = check_celery_connection()
    
    print("\n" + "=" * 50)
    if redis_ok and django_ok:
        print("🎉 Redis和Django配置正常!")
        if celery_ok:
            print("🎉 Celery连接正常!")
        else:
            print("💡 需要启动Celery Worker")
        sys.exit(0)
    else:
        print("❌ 存在配置问题")
        sys.exit(1)