import abc
import ipaddress
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class BaseScanner(abc.ABC):
    """扫描器基类，定义扫描器的通用接口"""
    
    def __init__(self, target: str, ports: str = "1-1000", options: Dict = None):
        """
        初始化扫描器
        
        Args:
            target: 扫描目标，可以是IP、网段或域名
            ports: 端口范围，如 "80,443,1-1000"
            options: 扫描选项字典
        """
        self.target = target
        self.ports = ports
        self.options = options or {}
        self.results = []
    
    @abc.abstractmethod
    def execute_scan(self, scan_type: str) -> List[Dict[str, Any]]:
        """执行扫描，返回结果列表"""
        pass
    
    def validate_target(self) -> bool:
        """验证目标地址是否合法"""
        try:
            # 尝试解析为IP地址或网络
            if '/' in self.target:
                ipaddress.ip_network(self.target, strict=False)
            else:
                ipaddress.ip_address(self.target)
            return True
        except ValueError:
            # 可能是域名，暂时认为合法
            return True
    
    def parse_ports(self) -> List[int]:
        """解析端口范围字符串为端口列表"""
        ports = []
        try:
            for part in self.ports.split(','):
                part = part.strip()
                if '-' in part:
                    # 处理端口范围，如 "1-100"
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    # 处理单个端口
                    ports.append(int(part))
            return sorted(set(ports))  # 去重并排序
        except ValueError as e:
            logger.error(f"端口解析错误: {e}")
            return []