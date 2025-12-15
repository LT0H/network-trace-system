import threading
import time
from queue import Queue, Empty
from .task import BaseTask, TaskStatus, NetworkTask, AnalysisTask, UpdateTask
from ..attack_signatures.update_signatures import SignatureManager
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("TaskManager")

class TaskManager:
    """任务管理器：负责任务的调度、执行和监控"""
    def __init__(self, max_workers=5):
        self.task_queue = Queue()
        self.active_tasks = {}  # {task_id: BaseTask}
        self.completed_tasks = {}  # {task_id: BaseTask}
        self.worker_threads = []
        self.max_workers = max_workers
        self.running = False
        self.signature_manager = SignatureManager()  # 关联特征库管理器

    def start(self):
        """启动任务管理器"""
        if self.running:
            logger.warning("任务管理器已在运行")
            return
        self.running = True
        # 启动工作线程
        for i in range(self.max_workers):
            thread = threading.Thread(target=self._worker, name=f"task_worker_{i}", daemon=True)
            self.worker_threads.append(thread)
            thread.start()
        logger.info(f"任务管理器启动，工作线程数：{self.max_workers}")

    def stop(self):
        """停止任务管理器"""
        self.running = False
        # 等待工作线程结束
        for thread in self.worker_threads:
            thread.join()
        self.worker_threads.clear()
        logger.info("任务管理器已停止")

    def add_task(self, task: BaseTask):
        """添加任务到队列"""
        if not isinstance(task, BaseTask):
            raise ValueError("任务必须是BaseTask的子类")
        self.task_queue.put(task)
        self.active_tasks[task.task_id] = task
        logger.info(f"添加任务：{task.task_id} ({task.task_name})")
        return task.task_id

    def get_task_status(self, task_id):
        """获取任务状态"""
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            return self.completed_tasks[task_id]
        else:
            return None

    def cancel_task(self, task_id):
        """取消任务"""
        task = self.get_task_status(task_id)
        if not task:
            return False
        if task.status in [TaskStatus.RUNNING, TaskStatus.PENDING]:
            task.cancel()
            logger.info(f"任务已取消：{task_id}")
            return True
        return False

    def list_tasks(self, status=None):
        """列出任务（可选按状态过滤）"""
        all_tasks = {**self.active_tasks,** self.completed_tasks}
        if status:
            return [t for t in all_tasks.values() if t.status == status]
        return list(all_tasks.values())

    def _worker(self):
        """工作线程：处理任务队列"""
        while self.running:
            try:
                task = self.task_queue.get(timeout=1)  # 1秒超时，便于检查running状态
                try:
                    self._execute_task(task)
                except Exception as e:
                    task.fail(f"任务执行异常：{str(e)}")
                    logger.error(f"任务执行失败 {task.task_id}：{str(e)}", exc_info=True)
                finally:
                    # 移动到已完成任务
                    self.active_tasks.pop(task.task_id, None)
                    self.completed_tasks[task.task_id] = task
                    self.task_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"工作线程异常：{str(e)}", exc_info=True)

    def _execute_task(self, task: BaseTask):
        """执行具体任务"""
        logger.info(f"开始执行任务：{task.task_id} ({task.task_name})")
        task.start()

        if isinstance(task, NetworkTask):
            self._run_network_task(task)
        elif isinstance(task, AnalysisTask):
            self._run_analysis_task(task)
        elif isinstance(task, UpdateTask):
            self._run_update_task(task)
        else:
            raise NotImplementedError(f"不支持的任务类型：{type(task)}")

    def _run_network_task(self, task: NetworkTask):
        """执行网络监控任务"""
        try:
            # 模拟网络监控（实际应调用抓包库）
            for i in range(10):
                time.sleep(task.duration / 10)  # 分步模拟进度
                task.update_progress(i * 10)
                if task.status == TaskStatus.CANCELLED:
                    return

            # 模拟结果
            task.complete({
                "captured_packets": 15600,
                "dropped_packets": 120,
                "output_file": task.output_file or f"/tmp/capture_{task.task_id}.pcap"
            })
            logger.info(f"网络监控任务完成：{task.task_id}")
        except Exception as e:
            task.fail(str(e))

    def _run_analysis_task(self, task: AnalysisTask):
        """执行数据包分析任务"""
        try:
            # 模拟分析过程
            for i in range(10):
                time.sleep(1)  # 模拟分析步骤
                task.update_progress(i * 10)
                if task.status == TaskStatus.CANCELLED:
                    return

            # 模拟分析结果（实际应调用特征库匹配）
            task.complete({
                "threat_score": 0.75,
                "detected_attacks": 12,
                "analysis_report": f"/tmp/report_{task.task_id}.json"
            })
            logger.info(f"分析任务完成：{task.task_id}")
        except Exception as e:
            task.fail(str(e))

    def _run_update_task(self, task: UpdateTask):
        """执行特征库更新任务"""
        try:
            task.update_progress(10)
            if task.update_source == "remote":
                # 调用特征库远程更新
                result = self.signature_manager.update_from_remote()
            else:
                # 调用特征库本地更新
                result = self.signature_manager.update_from_local_file(task.source_path)
            
            task.update_progress(90)
            if result["status"] == "success":
                task.complete(result)
                logger.info(f"更新任务完成：{task.task_id}")
            else:
                task.fail(result["message"])
        except Exception as e:
            task.fail(str(e))