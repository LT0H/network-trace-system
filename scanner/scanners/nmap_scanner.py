from typing import List, Dict, Any
import nmap
import json
from .base import BaseScanner
import logging

logger = logging.getLogger(__name__)

class NMAPScanner(BaseScanner):
    """基于Nmap的扫描器实现"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nm = nmap.PortScanner()
    
    def execute_scan(self, scan_type: str) -> List[Dict]:
        """执行Nmap扫描"""
        if not self.validate_target():
            return [{'error': '目标地址不合法'}]
        
        # 构建Nmap参数
        arguments = self._build_arguments(scan_type)
        
        try:
            logger.info(f"开始Nmap扫描: {self.target} 参数: {arguments}")
            
            # 执行扫描
            scan_result = self.nm.scan(hosts=self.target, ports=self.ports, arguments=arguments)
            
            return self._parse_nmap_result(scan_result)
            
        except Exception as e:
            logger.error(f"Nmap扫描出错: {e}")
            return [{'error': f'Nmap扫描失败: {str(e)}'}]
    
    def _build_arguments(self, scan_type: str) -> str:
        """根据扫描类型构建Nmap参数"""
        arguments = []
        
        # 基础参数
        arguments.extend(['-v', '--open'])
        
        # 根据扫描类型添加参数
        if scan_type == 'SYN_SCAN':
            arguments.append('-sS')
        elif scan_type == 'UDP_SCAN':
            arguments.append('-sU')
        elif scan_type == 'OS_DETECTION':
            arguments.extend(['-O', '--osscan-guess'])
        elif scan_type == 'SERVICE_DETECTION':
            arguments.append('-sV')
        elif scan_type == 'FULL_SCAN':
            arguments.extend(['-A', '-T4'])
        
        # 添加自定义选项
        if self.options.get('aggressive_timing'):
            arguments.append('-T4')
        if self.options.get('service_version'):
            arguments.append('-sV')
        if self.options.get('os_detection'):
            arguments.append('-O')
        
        return ' '.join(arguments)
    
    def _parse_nmap_result(self, scan_result: Dict) -> List[Dict]:
        """解析Nmap扫描结果"""
        results = []
        
        for host, host_data in scan_result['scan'].items():
            if host_data['status']['state'] != 'up':
                continue
            
            # 主机信息
            host_info = {
                'ip_address': host,
                'hostname': host_data['hostnames'][0]['name'] if host_data['hostnames'] else '',
                'state': 'up',
                'ttl': None  # Nmap不直接提供TTL
            }
            
            # 端口信息
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port, port_data in host_data[protocol].items():
                        result = host_info.copy()
                        result.update({
                            'port': port,
                            'protocol': protocol,
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'service_version': port_data.get('version', ''),
                            'fingerprint': {
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', '')
                            }
                        })
                        results.append(result)
            
            # 如果没有端口信息，只添加主机信息
            if not any(proto in host_data for proto in ['tcp', 'udp']):
                results.append(host_info)
        
        return results