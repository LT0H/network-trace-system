import json
import logging
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime
from django.conf import settings

logger = logging.getLogger(__name__)

class NetworkTopology:
    """网络拓扑图生成器"""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.topology_dir = settings.ANALYSIS_RESULT_PATH / "topology"
        self.topology_dir.mkdir(exist_ok=True)
    
    def add_flow_data(self, flow_data):
        """添加流量数据到拓扑图"""
        try:
            for flow in flow_data.get("flows", []):
                src_ip = flow.get("src_ip")
                dst_ip = flow.get("dst_ip")
                protocol = flow.get("protocol", "unknown")
                src_port = flow.get("src_port", "unknown")
                dst_port = flow.get("dst_port", "unknown")
                bytes_transferred = flow.get("total_bytes", 0)
                
                if src_ip and dst_ip:
                    # 添加节点
                    self.graph.add_node(src_ip, label=src_ip)
                    self.graph.add_node(dst_ip, label=dst_ip)
                    
                    # 添加边，记录协议、端口和流量大小
                    edge_key = (src_ip, dst_ip, protocol, src_port, dst_port)
                    if self.graph.has_edge(src_ip, dst_ip, key=edge_key):
                        # 更新已有边的流量
                        current_bytes = self.graph.edges[src_ip, dst_ip, edge_key].get("bytes", 0)
                        self.graph.edges[src_ip, dst_ip, edge_key]["bytes"] = current_bytes + bytes_transferred
                    else:
                        # 添加新边
                        self.graph.add_edge(
                            src_ip, dst_ip, 
                            key=edge_key,
                            protocol=protocol,
                            src_port=src_port,
                            dst_port=dst_port,
                            bytes=bytes_transferred
                        )
            return True
        except Exception as e:
            logger.error(f"添加流量数据到拓扑图失败: {e}")
            return False
    
    def load_from_analysis_file(self, analysis_file):
        """从分析结果文件加载数据"""
        try:
            with open(analysis_file, 'r') as f:
                data = json.load(f)
            return self.add_flow_data(data)
        except Exception as e:
            logger.error(f"从文件加载拓扑数据失败: {e}")
            return False
    
    def generate_topology_image(self, task_id):
        """生成拓扑图并保存"""
        try:
            if len(self.graph.nodes) == 0:
                logger.warning("没有数据可生成拓扑图")
                return None
            
            # 创建图形
            plt.figure(figsize=(12, 8))
            
            # 使用弹簧布局
            pos = nx.spring_layout(self.graph, k=0.3, iterations=50)
            
            # 绘制节点
            nx.draw_networkx_nodes(self.graph, pos, node_size=500, node_color='lightblue')
            
            # 绘制边
            nx.draw_networkx_edges(self.graph, pos, arrowstyle='->', arrowsize=10)
            
            # 绘制节点标签
            nx.draw_networkx_labels(self.graph, pos, font_size=10)
            
            # 绘制边标签（协议和端口）
            edge_labels = {}
            for u, v, key, data in self.graph.edges(keys=True, data=True):
                edge_labels[(u, v, key)] = f"{data['protocol']}: {data['src_port']}->{data['dst_port']}"
            
            nx.draw_networkx_edge_labels(
                self.graph, pos, edge_labels=edge_labels, 
                font_size=8, label_pos=0.3
            )
            
            # 保存图像
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            image_path = self.topology_dir / f"topology_{task_id}_{timestamp}.png"
            plt.savefig(image_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"拓扑图已保存到: {image_path}")
            return str(image_path)
            
        except Exception as e:
            logger.error(f"生成拓扑图失败: {e}")
            return None
    
    def clear(self):
        """清空拓扑图数据"""
        self.graph.clear()