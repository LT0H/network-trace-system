import scapy.all as scapy
import nmap
import time
import threading
from datetime import datetime

class ActiveProbe:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {}  # 存储扫描结果

    def tcp_syn_scan(self, target_ip, ports="1-1000", timeout=10):
        """TCP SYN半开放扫描（需管理员权限）- 生产环境核心逻辑"""
        start_time = datetime.now()
        try:
            # nmap SYN扫描：-sS（SYN扫描）、-v（详细输出）、-n（不解析DNS）
            self.nm.scan(target_ip, ports, "-sS -v -n", timeout=timeout)
            
            # 解析扫描结果
            result = {
                "target": target_ip,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "open_ports": []
            }
            
            if target_ip in self.nm.all_hosts():
                for proto in self.nm[target_ip].all_protocols():
                    ports = self.nm[target_ip][proto].keys()
                    for port in ports:
                        if self.nm[target_ip][proto][port]['state'] == 'open':
                            result["open_ports"].append({
                                "port": port,
                                "state": self.nm[target_ip][proto][port]['state'],
                                "service": self.nm[target_ip][proto][port].get('name', 'unknown'),
                                "product": self.nm[target_ip][proto][port].get('product', 'unknown')
                            })
            
            self.scan_results[target_ip] = result
            return result
        except Exception as e:
            return {"error": f"SYN扫描失败: {str(e)}"}

    def detect_anomaly_traffic(self, target_ip, duration=30):
        """发送异常流量并捕获RTT/TTL，用于攻击特征提取 - 生产环境核心逻辑"""
        anomaly_patterns = [
            {"flags": "FPU", "payload": b"malicious_test_payload_123"},  # 异常标志位（FIN+PSH+URG）
            {"flags": "S", "sport": 65535, "dport": 22, "payload": b"\x00"*1500},  # 超大SYN包
            {"flags": "A", "dport": 80, "payload": b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"}  # 路径遍历试探
        ]
        
        results = []
        for idx, pattern in enumerate(anomaly_patterns):
            try:
                # 构造异常数据包
                packet = scapy.IP(dst=target_ip)/scapy.TCP(
                    sport=pattern.get("sport", 12345 + idx),
                    dport=pattern.get("dport", 80),
                    flags=pattern.get("flags", "S")
                )/pattern.get("payload", b"")
                
                # 发送数据包并捕获响应，计算RTT
                start = time.time()
                reply = scapy.sr1(packet, timeout=2, verbose=0)
                rtt = (time.time() - start) * 1000 if reply else None
                
                # 提取TTL和其他信息
                results.append({
                    "pattern_id": idx + 1,
                    "pattern": pattern,
                    "has_response": bool(reply),
                    "rtt_ms": round(rtt, 2) if rtt else None,
                    "ttl": reply.ttl if reply else None,
                    "src_ip": reply.src if reply else None,
                    "tcp_flags": scapy.TCP(reply.payload).flags if reply else None
                })
            except Exception as e:
                results.append({
                    "pattern_id": idx + 1,
                    "pattern": pattern,
                    "error": str(e)
                })
        
        return {
            "target": target_ip,
            "duration_seconds": duration,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "anomaly_results": results
        }

    def run_background_scan(self, target_ip, callback=None):
        """后台异步执行扫描（不阻塞主线程）- 生产环境核心逻辑"""
        def task():
            result = self.tcp_syn_scan(target_ip)
            if callback:
                callback(result)  # 扫描完成后执行回调（如存入ES）
        
        scan_thread = threading.Thread(target=task, daemon=True)
        scan_thread.start()
        return {"status": "scan started", "thread_id": scan_thread.ident}