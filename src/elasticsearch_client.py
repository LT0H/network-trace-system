from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError, ConnectionError
import pandas as pd
from datetime import datetime

class ESClient:
    def __init__(self, hosts=["127.0.0.1:9200"], username="", password=""):
        """
        初始化ES客户端，兼容仅IP/IP:端口格式，避免索引越界
        :param hosts: ES地址列表，如["127.0.0.1:9200"]
        :param username: ES用户名（若无则留空）
        :param password: ES密码（若无则留空）
        """
        try:
            # 处理地址格式，确保每个地址都有IP+端口
            processed_hosts = []
            for host in hosts:
                # 拆分IP和端口，端口默认9200
                if ":" in host:
                    ip, port = host.split(":", 1)  # 只拆分一次，避免端口含冒号
                else:
                    ip = host
                    port = "9200"  # 默认端口
                processed_hosts.append({"host": ip, "port": port})
            
            # 初始化ES客户端
            if username and password:
                self.es = Elasticsearch(
                    processed_hosts,
                    basic_auth=(username, password),
                    timeout=30
                )
            else:
                self.es = Elasticsearch(processed_hosts, timeout=30)
            
            # 验证连接
            if self.es.ping():
                print("✅ ES客户端初始化成功")
            else:
                raise Exception("ES连接失败：ping不通")
        
        except IndexError as e:
            # 捕获元组索引越界异常
            raise Exception(f"ES地址解析失败：{str(e)}，请检查地址格式（正确示例：127.0.0.1:9200）")
        except Exception as e:
            raise Exception(f"ES客户端初始化失败：{str(e)}")
    
    def insert_data(self, index_name, data):
        """插入数据到ES"""
        try:
            resp = self.es.index(index=index_name, document=data)
            return resp
        except Exception as e:
            raise Exception(f"ES插入数据失败：{str(e)}")

    def _create_index_if_not_exists(self):
        """创建索引（如果不存在），定义字段映射 - 生产环境核心逻辑"""
        if not self.es.indices.exists(index=self.index):
            mapping = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0  # 生产环境建议根据集群配置调整
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"},
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "protocol_name": {"type": "keyword"},
                        "flow_duration": {"type": "integer"},
                        "total_fwd_packets": {"type": "integer"},
                        "total_bwd_packets": {"type": "integer"},
                        "rtt": {"type": "float"},
                        "ttl": {"type": "integer"},
                        "ttl_variance": {"type": "float"},
                        "payload": {"type": "text"},
                        "malicious_label": {"type": "keyword"},
                        "malicious_reason": {"type": "text"},
                        "scan_task_id": {"type": "keyword"},  # 关联扫描任务ID
                        "probe_type": {"type": "keyword"}  # 主动/被动探测标记
                    }
                }
            }
            try:
                self.es.indices.create(index=self.index, body=mapping)
                print(f"索引 {self.index} 创建成功")
            except RequestError as e:
                print(f"创建索引失败：{str(e)}")

    def preprocess_data(self, df):
        """
        数据预处理：标准化字段名、格式转换，适配ES索引 - 生产环境核心逻辑
        :param df: 流量数据DataFrame
        :return: 可批量插入的文档列表
        """
        if df.empty:
            return []
        
        df = df.copy()
        # 1. 标准化字段名（适配ES映射）
        field_mapping = {
            "Src IP": "src_ip",
            "Dst IP": "dst_ip",
            "Src Port": "src_port",
            "Dst Port": "dst_port",
            "Protocol": "protocol",
            "Protocol_Name": "protocol_name",
            "Flow Duration": "flow_duration",
            "Total Fwd Packets": "total_fwd_packets",
            "Total Bwd Packets": "total_bwd_packets",
            "RTT": "rtt",
            "TTL": "ttl",
            "TTL Variance": "ttl_variance",
            "Payload": "payload",
            "malicious_label": "malicious_label",
            "malicious_reason": "malicious_reason"
        }
        df.rename(columns=field_mapping, inplace=True)
        
        # 2. 添加通用字段
        df["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        df["scan_task_id"] = df.get("scan_task_id", "production_task")
        df["probe_type"] = df.get("probe_type", "passive")  # 默认被动探测
        
        # 3. 转换为字典列表
        docs = df.to_dict('records')
        # 清理空值（ES不支持None）
        for doc in docs:
            for k, v in list(doc.items()):
                if pd.isna(v) or v is None:
                    doc[k] = "" if isinstance(v, str) else 0
        
        return docs

    def bulk_insert(self, df, batch_size=1000):
        """
        批量插入数据到ES - 生产环境核心逻辑
        :param df: 流量数据DataFrame
        :param batch_size: 每批插入的文档数
        :return: 插入结果
        """
        if self.es is None or df.empty:
            return {"status": "failed", "message": "ES客户端未初始化或无数据"}
        
        docs = self.preprocess_data(df)
        if not docs:
            return {"status": "success", "message": "无数据可插入"}
        
        # 分批插入
        success_count = 0
        fail_count = 0
        total_docs = len(docs)
        
        for i in range(0, total_docs, batch_size):
            batch = docs[i:i+batch_size]
            actions = []
            for doc in batch:
                actions.append({"index": {"_index": self.index}})
                actions.append(doc)
            
            try:
                response = self.es.bulk(body=actions)
                # 统计成功/失败数
                success = sum(1 for item in response["items"] if item["index"]["status"] == 201)
                fail = len(batch) - success
                success_count += success
                fail_count += fail
                
                if response["errors"]:
                    print(f"批量{i//batch_size + 1}插入存在错误：{response['items']}")
            except Exception as e:
                fail_count += len(batch)
                print(f"批量{i//batch_size + 1}插入失败：{str(e)}")
        
        return {
            "status": "success" if fail_count == 0 else "partial",
            "total": total_docs,
            "success": success_count,
            "failed": fail_count,
            "message": f"批量插入完成：成功{success_count}条，失败{fail_count}条"
        }

    def query_malicious_flows(self, hours=24, risk_levels=None):
        """
        查询最近N小时的恶意流量 - 生产环境核心逻辑
        :param hours: 时间范围（小时）
        :param risk_levels: 风险等级列表（如["critical", "high"]）
        :return: 查询结果
        """
        if self.es is None:
            return {"error": "ES客户端未初始化"}
        
        # 构建查询条件
        query = {
            "size": 1000,  # 生产环境可根据需求调整
            "query": {
                "bool": {
                    "must": [
                        {"term": {"malicious_label": "恶意"}},
                        {"range": {"timestamp": {"gte": f"now-{hours}h", "lt": "now"}}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        
        # 添加风险等级过滤
        if risk_levels and isinstance(risk_levels, list):
            query["query"]["bool"]["filter"] = {
                "terms": {"malicious_reason.risk": risk_levels}
            }
        
        try:
            response = self.es.search(index=self.index, body=query)
            # 解析结果
            hits = response["hits"]["hits"]
            results = [{"_id": hit["_id"], "_source": hit["_source"]} for hit in hits]
            
            return {
                "status": "success",
                "total": response["hits"]["total"]["value"],
                "data": results
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_protocol_distribution(self):
        """查询协议分布统计（用于前端图表）- 生产环境核心逻辑"""
        if self.es is None:
            return {"error": "ES客户端未初始化"}
        
        agg_query = {
            "size": 0,
            "aggs": {
                "protocol_dist": {
                    "terms": {"field": "protocol_name.keyword", "size": 10}
                }
            }
        }
        
        try:
            response = self.es.search(index=self.index, body=agg_query)
            buckets = response["aggregations"]["protocol_dist"]["buckets"]
            
            return {
                "status": "success",
                "labels": [bucket["key"] for bucket in buckets],
                "counts": [bucket["doc_count"] for bucket in buckets]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}