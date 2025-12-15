import uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"       # 等待中
    RUNNING = "running"       # 运行中
    COMPLETED = "completed"   # 已完成
    FAILED = "failed"         # 失败
    CANCELLED = "cancelled"   # 已取消

class TaskType(Enum):
    """任务类型枚举"""
    NETWORK_MONITOR = "network_monitor"  # 网络监控
    PACKET_ANALYSIS = "packet_analysis"  # 包分析
    SIGNATURE_UPDATE = "signature_update"  # 特征库更新
    REPORT_GENERATION = "report_generation"  # 报告生成

@dataclass
class BaseTask:
    """任务基类"""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_name: str = "未命名任务"
    task_type: TaskType = TaskType.NETWORK_MONITOR
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: datetime = None
    completed_at: datetime = None
    progress: int = 0  # 0-100
    result: dict = field(default_factory=dict)
    error: str = ""

    def start(self):
        """启动任务"""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now()
        self.progress = 0

    def update_progress(self, value):
        """更新任务进度"""
        self.progress = min(max(int(value), 0), 100)

    def complete(self, result=None):
        """完成任务"""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now()
        self.progress = 100
        if result:
            self.result = result

    def fail(self, error_msg):
        """任务失败"""
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.now()
        self.error = error_msg

    def cancel(self):
        """取消任务"""
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.now()

@dataclass
class NetworkTask(BaseTask):
    """网络监控任务"""
    interface: str = "eth0"  # 监控网卡
    filter: str = ""  # BPF过滤规则
    duration: int = 3600  # 监控时长(秒)
    output_file: str = ""  # 输出文件路径

    def __post_init__(self):
        self.task_type = TaskType.NETWORK_MONITOR
        self.task_name = f"网络监控_{self.interface}"

@dataclass
class AnalysisTask(BaseTask):
    """数据包分析任务"""
    input_file: str = ""  # 输入文件路径
    analysis_type: str = "full"  # full/quick/attack_only
    threshold: float = 0.8  # 威胁评分阈值

    def __post_init__(self):
        self.task_type = TaskType.PACKET_ANALYSIS
        self.task_name = f"包分析_{self.input_file.split('/')[-1]}"

@dataclass
class UpdateTask(BaseTask):
    """特征库更新任务"""
    update_source: str = "remote"  # remote/local
    source_path: str = ""  # 本地更新包路径或远程URL

    def __post_init__(self):
        self.task_type = TaskType.SIGNATURE_UPDATE
        self.task_name = f"特征库更新_{self.update_source}"