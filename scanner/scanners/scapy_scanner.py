from typing import List, Dict, Any
import time
import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from .base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class ScapyScanner(BaseScanner):
    """基于Scapy的扫描器实现"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeout = self.options.get('timeout', 2)
        self.retries = self.options.get('retries', 1)
    
    def execute_scan(self, scan_type: str) -> List[Dict]:
        """根据扫描类型执行相应的扫描"""
        if not self.validate_target():
            return [{'error': '目标地址不合法'}]
        
        if scan_type == 'SYN_SCAN':
            return self.syn_scan()
        elif scan_type == 'UDP_SCAN':
            return self.udp_scan()
        elif scan_type == 'PING_SWEEP':
            return self.ping_sweep()
        else:
            return [{'error': f'不支持的扫描类型: {scan_type}'}]
    
    def syn_scan(self) -> List[Dict]:
        """SYN端口扫描"""
        results = []
        ports = self.parse_ports()
        
        if not ports:
            return [{'error': '没有有效的端口可扫描'}]
        
        logger.info(f"开始SYN扫描: {self.target} 端口: {len(ports)}个")
        
        for port in ports:
            try:
                # 创建SYN包
                pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
                start_time = time.time()
                
                # 发送包并接收响应
                resp = sr1(pkt, timeout=self.timeout, retry=self.retries, verbose=0)
                rtt = (time.time() - start_time) * 1000  # 转换为毫秒
                
                result = {
                    'ip_address': self.target,
                    'port': port,
                    'protocol': 'tcp',
                    'rtt': round(rtt, 2)
                }
                
                if resp is None:
                    # 没有响应，可能是过滤状态
                    result['state'] = 'filtered'
                elif resp.haslayer(TCP):
                    tcp_layer = resp.getlayer(TCP)
                    if tcp_layer.flags == 0x12:  # SYN-ACK
                        result['state'] = 'open'
                        # 发送RST包关闭连接
                        rst_pkt = IP(dst=self.target)/TCP(dport=port, flags="R")
                        send(rst_pkt, verbose=0)
                    elif tcp_layer.flags == 0x14:  # RST-ACK
                        result['state'] = 'closed'
                    else:
                        result['state'] = 'unknown'
                else:
                    result['state'] = 'unknown'
                
                results.append(result)
                logger.debug(f"端口 {port}: {result['state']}")
                
            except Exception as e:
                logger.error(f"扫描端口 {port} 时出错: {e}")
                results.append({
                    'ip_address': self.target,
                    'port': port,
                    'state': 'error',
                    'error': str(e)
                })
        
        return results
    
    def udp_scan(self) -> List[Dict]:
        """UDP端口扫描"""
        results = []
        ports = self.parse_ports()[:100]  # UDP扫描较慢，限制端口数量
        
        logger.info(f"开始UDP扫描: {self.target} 端口: {len(ports)}个")
        
        for port in ports:
            try:
                # 创建UDP包
                pkt = IP(dst=self.target)/UDP(dport=port)
                start_time = time.time()
                
                # 发送UDP包
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                rtt = (time.time() - start_time) * 1000
                
                result = {
                    'ip_address': self.target,
                    'port': port,
                    'protocol': 'udp',
                    'rtt': round(rtt, 2)
                }
                
                if resp is None:
                    # 没有响应，可能是开放或过滤
                    result['state'] = 'open|filtered'
                elif resp.haslayer(ICMP):
                    icmp_layer = resp.getlayer(ICMP)
                    if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
                        # 目标不可达，端口关闭
                        result['state'] = 'closed'
                    else:
                        result['state'] = 'filtered'
                elif resp.haslayer(UDP):
                    result['state'] = 'open'
                else:
                    result['state'] = 'unknown'
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"UDP扫描端口 {port} 时出错: {e}")
                results.append({
                    'ip_address': self.target,
                    'port': port,
                    'state': 'error',
                    'error': str(e)
                })
        
        return results
    
    def ping_sweep(self) -> List[Dict]:
        """Ping扫描发现活跃主机"""
        results = []
        
        try:
            # 如果是网段，扫描整个网段
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            else:
                targets = [self.target]
            
            for target_ip in targets:
                try:
                    # 发送ICMP Echo请求
                    pkt = IP(dst=target_ip)/ICMP()
                    start_time = time.time()
                    
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                    rtt = (time.time() - start_time) * 1000
                    
                    if resp is not None:
                        results.append({
                            'ip_address': target_ip,
                            'state': 'up',
                            'rtt': round(rtt, 2),
                            'ttl': resp.ttl
                        })
                    
                except Exception as e:
                    logger.debug(f"Ping {target_ip} 失败: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Ping扫描出错: {e}")
            results.append({'error': str(e)})
        
        return results