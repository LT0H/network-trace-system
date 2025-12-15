"""主动探测模块：发送异常流量并捕获响应，用于攻击特征提取"""
import time
from datetime import datetime
import scapy.all as scapy

class ActiveProbe:
    def __init__(self):
        """初始化主动探测模块"""
        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe_results")
        os.makedirs(self.results_dir, exist_ok=True)
        print("主动探测模块初始化成功")

    def tcp_syn_scan(self, target_ip, ports=range(1, 1000)):
        """TCP SYN扫描"""
        try:
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            open_ports = []
            
            for port in ports:
                # 发送SYN包
                packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")
                response = scapy.sr1(packet, timeout=1, verbose=0)
                
                if response:
                    # 检查是否收到SYN-ACK响应
                    if scapy.TCP in response and response[scapy.TCP].flags == "SA":
                        open_ports.append({
                            "port": port,
                            "state": "open",
                            "service": self._get_service_name(port),
                            "product": ""  # 可扩展为获取服务版本信息
                        })
                        
                        # 发送RST包关闭连接
                        rst_packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="R")
                        scapy.send(rst_packet, verbose=0)
            
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 保存扫描结果
            result = {
                "target": target_ip,
                "start_time": start_time,
                "end_time": end_time,
                "open_ports": open_ports
            }
            
            self._save_probe_result("tcp_syn_scan", target_ip, result)
            return result
            
        except Exception as e:
            return {"error": str(e)}

    def _get_service_name(self, port):
        """获取端口对应的服务名称"""
        service_map = {
            80: "http",
            443: "https",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            135: "msrpc",
            445: "microsoft-ds",
            3306: "mysql",
            3389: "rdp"
        }
        return service_map.get(port, "")

    def detect_anomaly_traffic(self, target_ip, duration=30):
        """发送异常流量并捕获RTT/TTL，用于攻击特征提取"""
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
                result_item = {
                    "pattern_id": idx + 1,
                    "pattern": pattern,
                    "has_response": bool(reply),
                    "rtt_ms": round(rtt, 2) if rtt else None,
                    "ttl": reply.ttl if reply else None,
                    "src_ip": reply.src if reply else None,
                    "tcp_flags": str(scapy.TCP(reply.payload).flags) if reply else None
                }
                results.append(result_item)

            except Exception as e:
                results.append({
                    "pattern_id": idx + 1,
                    "pattern": pattern,
                    "error": str(e)
                })
        
        # 整理最终结果
        final_result = {
            "target": target_ip,
            "duration_seconds": duration,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "anomaly_results": results
        }
        
        # 保存结果
        self._save_probe_result("anomaly_detection", target_ip, final_result)
        
        return final_result

    def _save_probe_result(self, scan_type, target_ip, result):
        """保存探测结果到文件"""
        try:
            import json
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{scan_type}_{target_ip.replace('.', '_')}_{timestamp}.json"
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            
            # 更新最新结果链接
            latest_link = os.path.join(self.results_dir, f"latest_{scan_type}_{target_ip.replace('.', '_')}.json")
            if os.path.exists(latest_link):
                os.unlink(latest_link)
            os.symlink(filepath, latest_link)
            
            return filepath
        except Exception as e:
            print(f"保存探测结果失败：{str(e)}")
            return None

    def get_latest_anomaly_results(self, target_ip):
        """获取最新的异常检测结果"""
        try:
            import json
            latest_link = os.path.join(
                self.results_dir, 
                f"latest_anomaly_detection_{target_ip.replace('.', '_')}.json"
            )
            
            if not os.path.exists(latest_link):
                return None, "没有找到异常检测结果"
            
            with open(latest_link, 'r', encoding='utf-8') as f:
                result = json.load(f)
            
            return result, "成功获取异常检测结果"
        except Exception as e:
            return None, f"获取异常检测结果失败：{str(e)}"