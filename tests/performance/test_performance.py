import time
import pytest
from django.test import TestCase
from scanner.models import ScanTask
from scanner.tasks import run_scan_task

class PerformanceTest(TestCase):
    """性能测试"""
    
    def test_concurrent_task_processing(self):
        """测试并发任务处理能力"""
        import threading
        
        # 创建多个任务
        tasks = []
        for i in range(5):
            task = ScanTask.objects.create(
                name=f'性能测试任务{i}',
                target=f'192.168.1.{i+1}',
                scan_type='SYN_SCAN'
            )
            tasks.append(task)
        
        # 并发执行任务（模拟）
        start_time = time.time()
        
        threads = []
        for task in tasks:
            thread = threading.Thread(target=run_scan_task, args=(task.id,))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        print(f"并发执行5个任务耗时: {execution_time:.2f}秒")
        
        # 验证所有任务完成
        for task in tasks:
            task.refresh_from_db()
            self.assertIn(task.status, ['COMPLETED', 'FAILED'])
    
    def test_large_scale_result_handling(self):
        """测试大规模结果处理"""
        task = ScanTask.objects.create(
            name='大规模结果测试',
            target='192.168.1.0/24',
            scan_type='SYN_SCAN'
        )
        
        # 模拟大量扫描结果
        start_time = time.time()
        
        from scanner.models import ScanResult
        batch_size = 1000
        results = []
        
        for i in range(batch_size):
            results.append(ScanResult(
                task=task,
                ip_address=f'192.168.1.{i % 254 + 1}',
                port=80 + (i % 100),
                state='open' if i % 10 != 0 else 'closed',
                service='http'
            ))
        
        # 批量插入
        ScanResult.objects.bulk_create(results)
        end_time = time.time()
        
        insertion_time = end_time - start_time
        print(f"插入{ batch_size }条结果耗时: {insertion_time:.2f}秒")
        
        # 验证数据查询性能
        start_time = time.time()
        open_ports = ScanResult.objects.filter(task=task, state='open').count()
        end_time = time.time()
        
        query_time = end_time - start_time
        print(f"查询开放端口数量耗时: {query_time:.2f}秒")
        
        self.assertEqual(open_ports, batch_size * 9 // 10)  # 90%端口开放