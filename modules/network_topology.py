#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络拓扑可视化模块
"""

import os
import sys
import logging
import json
import math
from collections import defaultdict

import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import networkx as nx
from matplotlib.patches import FancyArrowPatch

from utils.common import ensure_dir_exists

class NetworkTopology:
    """
    网络拓扑图生成类，用于绘制网络拓扑图
    """
    
    def __init__(self, config=None):
        """
        初始化NetworkTopology实例
        
        Args:
            config (dict): 配置参数
        """
        self.logger = logging.getLogger(__name__)
        
        # 默认配置
        default_config = {
            'node_colors': {
                'host': '#1f77b4',      # 蓝色
                'router': '#ff7f0e',    # 橙色
                'server': '#2ca02c',    # 绿色
                'unknown': '#d62728'    # 红色
            },
            'edge_width': {
                'low': 1,
                'medium': 2,
                'high': 3
            },
            'figure_size': (12, 8),
            'node_size': 300,
            'font_size': 10,
            'dpi': 300
        }
        
        # 合并配置
        self.config = default_config
        if config:
            self.config.update(config)
        
        # 创建图形
        self.graph = nx.DiGraph()
        
        # 节点类型统计
        self.node_types = defaultdict(int)
        
        self.logger.info("网络拓扑图生成器已初始化")
    
    def add_node(self, node_id, node_type='unknown', **attributes):
        """
        添加网络节点
        
        Args:
            node_id (str): 节点ID
            node_type (str): 节点类型（host/router/server/unknown）
            **attributes: 其他节点属性
        """
        # 验证节点类型
        if node_type not in self.config['node_colors']:
            self.logger.warning(f"未知节点类型: {node_type}，使用默认类型")
            node_type = 'unknown'
        
        # 设置节点属性
        attributes['type'] = node_type
        attributes['color'] = self.config['node_colors'][node_type]
        
        # 添加节点
        self.graph.add_node(node_id, **attributes)
        
        # 更新节点类型统计
        self.node_types[node_type] += 1
        
        self.logger.debug(f"添加节点: ID={node_id}, 类型={node_type}")
    
    def add_edge(self, source, target, edge_type='default', weight=1, **attributes):
        """
        添加网络连接
        
        Args:
            source (str): 源节点ID
            target (str): 目标节点ID
            edge_type (str): 连接类型
            weight (int): 连接权重（用于确定线宽）
            **attributes: 其他连接属性
        """
        # 确保源节点和目标节点存在
        if source not in self.graph.nodes:
            self.add_node(source)
            self.logger.warning(f"添加边时源节点不存在，已自动创建: {source}")
        
        if target not in self.graph.nodes:
            self.add_node(target)
            self.logger.warning(f"添加边时目标节点不存在，已自动创建: {target}")
        
        # 确定线宽
        if weight <= 10:
            width = self.config['edge_width']['low']
        elif weight <= 100:
            width = self.config['edge_width']['medium']
        else:
            width = self.config['edge_width']['high']
        
        # 设置边属性
        attributes['type'] = edge_type
        attributes['weight'] = weight
        attributes['width'] = width
        
        # 添加边
        self.graph.add_edge(source, target, **attributes)
        
        self.logger.debug(f"添加连接: {source} -> {target}, 权重={weight}")
    
    def build_from_data(self, data):
        """
        从分析数据构建拓扑图
        
        Args:
            data (dict): 分析数据
        """
        self.logger.info("从数据构建网络拓扑图")
        
        # 清空现有图形
        self.graph.clear()
        self.node_types.clear()
        
        # 根据数据格式进行处理
        if isinstance(data, dict):
            # 检查是否是ws-traffic-analyze-kit的输出格式
            if 'flows' in data:
                self._build_from_flows(data['flows'])
            elif 'connections' in data:
                self._build_from_connections(data['connections'])
            elif 'nodes' in data and 'edges' in data:
                self._build_from_graph_data(data)
            else:
                # 尝试解析其他格式
                self._build_from_generic_data(data)
        elif isinstance(data, list):
            # 假设是连接列表
            self._build_from_connections(data)
        else:
            raise ValueError("不支持的数据格式")
        
        self.logger.info(f"拓扑图构建完成: 节点数={len(self.graph.nodes)}, 连接数={len(self.graph.edges)}")
        self.logger.info(f"节点类型统计: {dict(self.node_types)}")
    
    def _build_from_flows(self, flows):
        """
        从流量数据构建拓扑图
        
        Args:
            flows (list): 流量列表
        """
        # 统计IP地址出现频率
        ip_counts = defaultdict(int)
        
        # 处理每个流量
        for flow in flows:
            try:
                src_ip = flow.get('src_ip')
                dst_ip = flow.get('dst_ip')
                protocol = flow.get('protocol', 'unknown')
                bytes_count = flow.get('bytes', 0)
                
                if src_ip and dst_ip:
                    # 更新IP地址计数
                    ip_counts[src_ip] += bytes_count
                    ip_counts[dst_ip] += bytes_count
                    
                    # 确定节点类型（简单示例）
                    src_type = self._determine_node_type(src_ip, flow)
                    dst_type = self._determine_node_type(dst_ip, flow)
                    
                    # 添加节点
                    self.add_node(src_ip, src_type, ip=src_ip)
                    self.add_node(dst_ip, dst_type, ip=dst_ip)
                    
                    # 添加边
                    self.add_edge(
                        src_ip, 
                        dst_ip, 
                        edge_type=protocol,
                        weight=bytes_count,
                        protocol=protocol,
                        bytes=bytes_count,
                        packets=flow.get('packets', 0)
                    )
                    
            except Exception as e:
                self.logger.error(f"处理流量数据时发生错误: {e}")
                continue
    
    def _build_from_connections(self, connections):
        """
        从连接数据构建拓扑图
        
        Args:
            connections (list): 连接列表
        """
        for conn in connections:
            try:
                src = conn.get('source') or conn.get('src')
                dst = conn.get('target') or conn.get('dst')
                
                if src and dst:
                    # 添加节点
                    self.add_node(src, self._guess_node_type(src))
                    self.add_node(dst, self._guess_node_type(dst))
                    
                    # 添加边
                    self.add_edge(
                        src, 
                        dst, 
                        weight=conn.get('weight', 1),
                        **{k: v for k, v in conn.items() if k not in ['source', 'target', 'src', 'dst']}
                    )
                    
            except Exception as e:
                self.logger.error(f"处理连接数据时发生错误: {e}")
                continue
    
    def _build_from_graph_data(self, data):
        """
        从图形数据构建拓扑图
        
        Args:
            data (dict): 包含nodes和edges的图形数据
        """
        # 添加节点
        for node in data.get('nodes', []):
            try:
                node_id = node.get('id')
                if node_id:
                    node_type = node.get('type', 'unknown')
                    # 提取其他属性
                    attributes = {k: v for k, v in node.items() if k not in ['id', 'type']}
                    self.add_node(node_id, node_type, **attributes)
            except Exception as e:
                self.logger.error(f"添加节点时发生错误: {e}")
                continue
        
        # 添加边
        for edge in data.get('edges', []):
            try:
                source = edge.get('source') or edge.get('src')
                target = edge.get('target') or edge.get('dst')
                
                if source and target:
                    # 提取其他属性
                    attributes = {k: v for k, v in edge.items() if k not in ['source', 'target', 'src', 'dst']}
                    self.add_edge(source, target, **attributes)
            except Exception as e:
                self.logger.error(f"添加边时发生错误: {e}")
                continue
    
    def _build_from_generic_data(self, data):
        """
        尝试从通用数据构建拓扑图
        
        Args:
            data (dict): 通用数据
        """
        # 这是一个简单的实现，实际应用中可能需要更复杂的逻辑
        self.logger.warning("尝试从通用数据格式构建拓扑图，可能不准确")
        
        # 尝试查找可能的节点和连接
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    # 假设列表中的每个元素可能是一个连接
                    for item in value:
                        if isinstance(item, dict):
                            src = item.get('src_ip') or item.get('source') or item.get('src')
                            dst = item.get('dst_ip') or item.get('target') or item.get('dst')
                            
                            if src and dst:
                                self.add_node(src, self._guess_node_type(src))
                                self.add_node(dst, self._guess_node_type(dst))
                                self.add_edge(src, dst, weight=item.get('bytes', 1))
    
    def _determine_node_type(self, ip, flow_data):
        """
        根据IP地址和流量数据确定节点类型
        
        Args:
            ip (str): IP地址
            flow_data (dict): 流量数据
            
        Returns:
            str: 节点类型
        """
        # 这是一个简单的实现，实际应用中可能需要更复杂的逻辑
        
        # 根据端口号判断
        src_port = flow_data.get('src_port', 0)
        dst_port = flow_data.get('dst_port', 0)
        
        # 常见服务器端口
        server_ports = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            3306: 'mysql',
            5432: 'postgresql',
            8080: 'http-alt',
            8443: 'https-alt'
        }
        
        # 如果是流量的目标，且端口是常见服务器端口，则可能是服务器
        if flow_data.get('dst_ip') == ip and dst_port in server_ports:
            return 'server'
        
        # 如果是流量的源，且端口是高端口（>1024），则可能是普通主机
        if flow_data.get('src_ip') == ip and src_port > 1024:
            return 'host'
        
        # 简单的IP地址判断
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
            # 私有IP地址，可能是内部主机
            return 'host'
        
        # 默认未知类型
        return 'unknown'
    
    def _guess_node_type(self, node_id):
        """
        根据节点ID猜测节点类型
        
        Args:
            node_id (str): 节点ID
            
        Returns:
            str: 猜测的节点类型
        """
        # 这是一个非常简单的实现，实际应用中可能需要更复杂的逻辑
        
        # 如果是IP地址
        if '.' in node_id:
            # 私有IP地址范围
            if node_id.startswith('192.168.') or node_id.startswith('10.') or node_id.startswith('172.16.'):
                return 'host'
            else:
                # 公网IP，可能是服务器
                return 'server'
        
        # 如果包含特定关键字
        node_lower = node_id.lower()
        if any(keyword in node_lower for keyword in ['router', 'gw', 'gateway']):
            return 'router'
        elif any(keyword in node_lower for keyword in ['server', 'web', 'db', 'mail', 'ftp']):
            return 'server'
        
        # 默认未知类型
        return 'unknown'
    
    def draw_topology(self, output_file=None, show=True):
        """
        绘制网络拓扑图
        
        Args:
            output_file (str): 输出文件路径，None表示不保存
            show (bool): 是否显示图形
            
        Returns:
            matplotlib.figure.Figure: 生成的图形对象
        """
        if not self.graph.nodes:
            self.logger.warning("没有节点可绘制")
            return None
        
        self.logger.info(f"绘制网络拓扑图: 节点数={len(self.graph.nodes)}, 连接数={len(self.graph.edges)}")
        
        # 创建图形
        fig, ax = plt.subplots(figsize=self.config['figure_size'])
        
        # 设置图形标题
        plt.title('网络拓扑图', fontsize=16)
        
        # 准备节点位置
        # 使用spring布局算法，适合大多数网络拓扑
        pos = nx.spring_layout(self.graph, seed=42, k=0.3)
        
        # 准备节点绘制参数
        node_colors = [self.graph.nodes[n].get('color', self.config['node_colors']['unknown']) 
                       for n in self.graph.nodes]
        node_sizes = [self.config['node_size'] for _ in self.graph.nodes]
        node_labels = {n: n for n in self.graph.nodes}
        
        # 绘制节点
        nx.draw_networkx_nodes(
            self.graph, 
            pos, 
            ax=ax,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.8
        )
        
        # 绘制边
        edge_widths = [self.graph.edges[e].get('width', self.config['edge_width']['low']) 
                       for e in self.graph.edges]
        
        # 使用FancyArrowPatch绘制有向边
        for u, v, d in self.graph.edges(data=True):
            width = d.get('width', self.config['edge_width']['low'])
            arrow = FancyArrowPatch(
                pos[u], pos[v], 
                arrowstyle='->',
                connectionstyle='arc3,rad=.1',
                linewidth=width,
                color='gray',
                alpha=0.6
            )
            ax.add_patch(arrow)
        
        # 绘制节点标签
        nx.draw_networkx_labels(
            self.graph, 
            pos, 
            labels=node_labels,
            font_size=self.config['font_size'],
            font_color='black',
            ax=ax
        )
        
        # 添加图例
        self._add_legend(ax)
        
        # 设置图形属性
        ax.set_axis_off()
        plt.tight_layout()
        
        # 保存图形（如果指定了输出文件）
        if output_file:
            # 确保输出目录存在
            output_dir = os.path.dirname(output_file)
            if output_dir:
                ensure_dir_exists(output_dir)
            
            # 保存图形
            plt.savefig(output_file, dpi=self.config['dpi'], bbox_inches='tight')
            self.logger.info(f"拓扑图已保存至: {output_file}")
        
        # 显示图形（如果需要）
        if show and not output_file:
            plt.show()
        
        return fig
    
    def _add_legend(self, ax):
        """
        添加图例
        
        Args:
            ax (matplotlib.axes.Axes): matplotlib轴对象
        """
        from matplotlib.lines import Line2D
        
        # 节点类型图例
        node_legend_elements = []
        for node_type, color in self.config['node_colors'].items():
            if self.node_types[node_type] > 0:  # 只显示存在的节点类型
                node_legend_elements.append(
                    Line2D(
                        [0], [0], 
                        marker='o', 
                        color='w', 
                        markerfacecolor=color, 
                        markersize=10, 
                        label=f"{node_type.capitalize()} ({self.node_types[node_type]})"
                    )
                )
        
        # 添加节点类型图例
        if node_legend_elements:
            ax.legend(
                handles=node_legend_elements,
                title="节点类型",
                loc='upper left',
                bbox_to_anchor=(1, 1)
            )
    
    def export_graph(self, output_file, format='gexf'):
        """
        导出图形为文件
        
        Args:
            output_file (str): 输出文件路径
            format (str): 输出格式（gexf/graphml/json）
        """
        # 确保输出目录存在
        output_dir = os.path.dirname(output_file)
        if output_dir:
            ensure_dir_exists(output_dir)
        
        try:
            if format == 'gexf':
                # 导出为GEXF格式（Gephi支持）
                nx.write_gexf(self.graph, output_file)
            elif format == 'graphml':
                # 导出为GraphML格式
                nx.write_graphml(self.graph, output_file)
            elif format == 'json':
                # 导出为JSON格式
                graph_data = {
                    'nodes': [
                        {
                            'id': n,
                            **self.graph.nodes[n]
                        }
                        for n in self.graph.nodes
                    ],
                    'edges': [
                        {
                            'source': u,
                            'target': v,
                            **self.graph.edges[u, v]
                        }
                        for u, v in self.graph.edges
                    ]
                }
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(graph_data, f, indent=2, ensure_ascii=False)
            else:
                raise ValueError(f"不支持的导出格式: {format}")
            
            self.logger.info(f"图形已导出至: {output_file}, 格式={format}")
            
        except Exception as e:
            self.logger.error(f"导出图形失败: {e}")
            raise
    
    def get_statistics(self):
        """
        获取拓扑图统计信息
        
        Returns:
            dict: 统计信息
        """
        stats = {
            'nodes_count': len(self.graph.nodes),
            'edges_count': len(self.graph.edges),
            'node_types': dict(self.node_types),
            'density': nx.density(self.graph),
            'average_degree': sum(dict(self.graph.degree()).values()) / len(self.graph.nodes) if self.graph.nodes else 0
        }
        
        # 计算其他统计信息
        if self.graph.nodes:
            # 连通分量
            if nx.is_directed(self.graph):
                strongly_connected = list(nx.strongly_connected_components(self.graph))
                stats['strongly_connected_components'] = len(strongly_connected)
            else:
                connected = list(nx.connected_components(self.graph))
                stats['connected_components'] = len(connected)
            
            # 中心性指标
            try:
                degree_centrality = nx.degree_centrality(self.graph)
                stats['degree_centrality'] = {
                    'max': max(degree_centrality.values()),
                    'avg': sum(degree_centrality.values()) / len(degree_centrality)
                }
            except:
                pass
        
        return stats
    
    def clear(self):
        """
        清空拓扑图
        """
        self.graph.clear()
        self.node_types.clear()
        self.logger.info("拓扑图已清空")