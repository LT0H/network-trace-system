import logging
from scapy.all import IP, TCP, UDP, sr1, send
import time

logger = logging.getLogger(__name__)

class ScapyScanner:
    """基于Scapy的网络扫描器"""
    
    def __init__(self, task):
        self.task = task
        self.results = []
        
    def syn_scan(self, target, ports):
        """SYN扫描，不等待完整连接"""
        port_list = self._parse_ports(ports)
        total_ports = len(port_list)
        
        for i, port in enumerate(port_list):
            # 更新进度
            progress = int((i + 1) / total_ports * 100)
            self.task.progress = progress
            self.task.save()
            
            # 发送SYN包，不等待应答
            ip = IP(dst=target)
            tcp = TCP(dport=port, flags='S')
            packet = ip / tcp
            
            try:
                # 发送数据包但不等待响应
                send(packet, verbose=0)
                # 记录扫描尝试，无论是否有应答
                self.results.append({
                    'ip_address': target,
                    'port': port,
                    'state': 'scanned',  # 标记为已扫描，而非根据应答判断
                    'timestamp': time.time()
                })
            except Exception as e:
                logger.error(f"扫描端口 {port} 失败: {str(e)}")
            
            time.sleep(0.1)  # 避免发送过快
        
        return self.results
    
    def udp_scan(self, target, ports):
        """UDP扫描，不等待应答"""
        port_list = self._parse_ports(ports)
        total_ports = len(port_list)
        
        for i, port in enumerate(port_list):
            # 更新进度
            progress = int((i + 1) / total_ports * 100)
            self.task.progress = progress
            self.task.save()
            
            # 发送UDP包，不等待应答
            ip = IP(dst=target)
            udp = UDP(dport=port)
            packet = ip / udp
            
            try:
                # 发送数据包但不等待响应
                send(packet, verbose=0)
                # 记录扫描尝试
                self.results.append({
                    'ip_address': target,
                    'port': port,
                    'protocol': 'udp',
                    'state': 'scanned',
                    'timestamp': time.time()
                })
            except Exception as e:
                logger.error(f"扫描UDP端口 {port} 失败: {str(e)}")
            
            time.sleep(0.1)
        
        return self.results
    
    def _parse_ports(self, port_str):
        """解析端口字符串为端口列表"""
        ports = []
        for part in port_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return list(set(ports))  # 去重