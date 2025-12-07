from typing import List, Dict, Any
import time
import ipaddress
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, sr1, send, sr
from .base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class ScapyScanner(BaseScanner):
    """基于Scapy的主动扫描器（完善版）"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeout = self.options.get('timeout', 2)  # 超时时间（秒）
        self.retries = self.options.get('retries', 1)  # 重试次数
        self.interface = self.options.get('interface', None)  # 扫描使用的接口
    
    def execute_scan(self, scan_type: str) -> List[Dict]:
        """执行指定类型的扫描"""
        if not self.validate_target():
            return [{'error': '目标地址不合法（支持IP或网段，如192.168.1.1/24）'}]
        
        scan_methods = {
            'SYN_SCAN': self.syn_scan,
            'UDP_SCAN': self.udp_scan,
            'PING_SWEEP': self.ping_sweep
        }
        
        if scan_type not in scan_methods:
            return [{'error': f'不支持的扫描类型: {scan_type}'}]
        
        return scan_methods[scan_type]()
    
    def syn_scan(self) -> List[Dict]:
        """SYN半开扫描（隐蔽性好）"""
        results = []
        ports = self.parse_ports()  # 解析端口（支持1-100,8080格式）
        
        if not ports:
            return [{'error': '未指定有效端口（格式：1-100,8080）'}]
        
        logger.info(f"开始SYN扫描: {self.target} 端口: {ports}")
        
        for port in ports:
            try:
                # 构造SYN包
                pkt = IP(dst=self.target) / TCP(dport=port, flags="S", seq=1000)
                start_time = time.time()
                
                # 发送并等待响应（指定接口提高准确性）
                resp = sr1(
                    pkt,
                    timeout=self.timeout,
                    retry=self.retries,
                    verbose=0,
                    iface=self.interface
                )
                rtt = (time.time() - start_time) * 1000  # 响应时间（毫秒）
                
                result = {
                    'ip_address': self.target,
                    'port': port,
                    'protocol': 'tcp',
                    'rtt': round(rtt, 2),
                    'state': 'unknown'
                }
                
                if resp is None:
                    result['state'] = 'filtered'  # 无响应（可能被过滤）
                elif resp.haslayer(TCP):
                    tcp_flags = resp.getlayer(TCP).flags
                    if tcp_flags == 0x12:  # SYN-ACK（端口开放）
                        result['state'] = 'open'
                        # 发送RST包关闭连接（避免半开连接残留）
                        send(IP(dst=self.target)/TCP(dport=port, flags="R"), verbose=0, iface=self.interface)
                    elif tcp_flags == 0x14:  # RST-ACK（端口关闭）
                        result['state'] = 'closed'
                
                results.append(result)
                logger.debug(f"端口 {port} 状态: {result['state']}")
                
            except Exception as e:
                logger.error(f"扫描端口 {port} 失败: {e}")
                results.append({
                    'ip_address': self.target,
                    'port': port,
                    'state': 'error',
                    'error': str(e)
                })
        
        return results
    
    def udp_scan(self) -> List[Dict]:
        """UDP扫描（针对UDP服务）"""
        results = []
        ports = self.parse_ports()[:50]  # 限制端口数量（UDP扫描较慢）
        
        if not ports:
            return [{'error': '未指定有效端口'}]
        
        logger.info(f"开始UDP扫描: {self.target} 端口: {ports}")
        
        for port in ports:
            try:
                # 构造UDP包
                pkt = IP(dst=self.target) / UDP(dport=port)
                start_time = time.time()
                
                # 发送并等待响应
                resp = sr1(
                    pkt,
                    timeout=self.timeout,
                    retry=self.retries,
                    verbose=0,
                    iface=self.interface
                )
                rtt = (time.time() - start_time) * 1000
                
                result = {
                    'ip_address': self.target,
                    'port': port,
                    'protocol': 'udp',
                    'rtt': round(rtt, 2),
                    'state': 'unknown'
                }
                
                if resp is None:
                    result['state'] = 'open|filtered'  # 无响应（开放或过滤）
                elif resp.haslayer(ICMP):
                    # ICMP不可达表示端口关闭
                    if resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code in [1,2,3,9,10,13]:
                        result['state'] = 'closed'
                    else:
                        result['state'] = 'filtered'
                elif resp.haslayer(UDP):
                    result['state'] = 'open'  # 收到UDP响应
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"UDP扫描端口 {port} 失败: {e}")
                results.append({
                    'ip_address': self.target,
                    'port': port,
                    'state': 'error',
                    'error': str(e)
                })
        
        return results
    
    def ping_sweep(self) -> List[Dict]:
        """Ping扫描（发现活跃主机）"""
        results = []
        
        try:
            # 解析目标（支持单个IP或网段）
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            else:
                targets = [self.target]
            
            logger.info(f"开始Ping扫描: {self.target}（共{len(targets)}个主机）")
            
            for target_ip in targets:
                try:
                    # 发送ICMP Echo请求
                    pkt = IP(dst=target_ip) / ICMP(type=8, code=0)  # Echo Request
                    start_time = time.time()
                    
                    resp = sr1(
                        pkt,
                        timeout=self.timeout,
                        retry=self.retries-1,
                        verbose=0,
                        iface=self.interface
                    )
                    rtt = (time.time() - start_time) * 1000
                    
                    if resp and resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 0:
                        # 收到Echo Reply（主机存活）
                        results.append({
                            'ip_address': target_ip,
                            'state': 'up',
                            'rtt': round(rtt, 2),
                            'ttl': resp.ttl  # 生存时间（可推测操作系统）
                        })
                    else:
                        results.append({
                            'ip_address': target_ip,
                            'state': 'down',
                            'rtt': None
                        })
                
                except Exception as e:
                    logger.debug(f"Ping {target_ip} 失败: {e}")
                    results.append({
                        'ip_address': target_ip,
                        'state': 'error',
                        'error': str(e)
                    })
        
        except Exception as e:
            logger.error(f"Ping扫描出错: {e}")
            results.append({'error': str(e)})
        
        return results
    
    def parse_ports(self) -> List[int]:
        """解析端口字符串（如"1-10,8080"）为整数列表"""
        ports = []
        port_str = self.options.get('ports', '1-100')
        
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end)+1))
            else:
                ports.append(int(part))
        
        return list(set(ports))  # 去重
    
    def validate_target(self) -> bool:
        """验证目标IP/网段合法性"""
        try:
            if '/' in self.target:
                ipaddress.ip_network(self.target, strict=False)
            else:
                ipaddress.ip_address(self.target)
            return True
        except ValueError:
            return False