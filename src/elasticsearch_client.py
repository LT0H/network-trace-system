from elasticsearch import Elasticsearch, exceptions
import logging
import pandas as pd
from datetime import datetime

class ESClient:
    def __init__(self, hosts=["localhost:9200"], username="", password="", index="network_traffic"):
        self.index = index
        self.logger = logging.getLogger("ESClient")
        self.client = None
        try:
            # 修复连接格式（移除http前缀）
            self.client = Elasticsearch(
                hosts=hosts,
                basic_auth=(username, password) if username else None,
                request_timeout=30  # 延长超时时间
            )
            if not self.client.ping():
                raise exceptions.ConnectionError("无法连接到Elasticsearch服务")
            self._create_index_if_not_exists()
            self.logger.info(f"ES客户端初始化成功，索引：{self.index}")
        except Exception as e:
            self.logger.error(f"ES初始化失败：{str(e)}", exc_info=True)
            raise

    def _create_index_if_not_exists(self):
        """创建索引及映射（支持IP类型和日期类型）"""
        if not self.client.indices.exists(index=self.index):
            mapping = {
                "mappings": {
                    "properties": {
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"},
                        "flow_duration": {"type": "float"},
                        "packet_count": {"type": "integer"},
                        "byte_count": {"type": "integer"},
                        "is_malicious": {"type": "boolean"},
                        "attack_type": {"type": "keyword"},
                        "risk_level": {"type": "keyword"}
                    }
                }
            }
            self.client.indices.create(index=self.index, body=mapping)
            self.logger.info(f"索引{self.index}创建成功")

    def bulk_insert(self, dataframe):
        """批量插入DataFrame数据"""

        if self.es is None or df.empty:
            return {"status": "failed", "message": "ES客户端未初始化或无数据"}

        self._create_index_if_not_exists()
    
        docs = self.preprocess_data(df)

        if dataframe.empty:
            return {"success": False, "message": "无数据可插入"}
        
        try:
            actions = []
            for _, row in dataframe.iterrows():
                # 转换时间格式（兼容CICFlowMeter输出）
                if 'timestamp' in row and not pd.isna(row['timestamp']):
                    try:
                        row['timestamp'] = datetime.strptime(str(row['timestamp']), "%Y-%m-%d %H:%M:%S").isoformat()
                    except:
                        pass
                
                actions.append({"index": {"_index": self.index}})
                actions.append(row.to_dict())
            
            # 批量插入
            response = self.client.bulk(body=actions, refresh=True)
            if response.get("errors"):
                errors = [item for item in response["items"] if "error" in item["index"]]
                self.logger.warning(f"部分数据插入失败：{len(errors)}条错误")
                return {"success": False, "message": f"部分数据插入失败，错误数：{len(errors)}"}
            
            self.logger.info(f"成功插入{len(dataframe)}条数据到ES")
            return {"success": True, "message": f"插入{len(dataframe)}条数据", "count": len(dataframe)}
        except Exception as e:
            self.logger.error(f"批量插入失败：{str(e)}", exc_info=True)
            return {"success": False, "message": str(e)}

    def bulk_insert_from_file(self, json_file):
        """从JSON文件插入数据"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if "flows" not in data:
                return {"success": False, "message": "文件格式错误，缺少flows字段"}
            
            dataframe = pd.DataFrame(data["flows"])
            return self.bulk_insert(dataframe)
        except Exception as e:
            self.logger.error(f"从文件插入失败：{str(e)}", exc_info=True)
            return {"success": False, "message": str(e)}