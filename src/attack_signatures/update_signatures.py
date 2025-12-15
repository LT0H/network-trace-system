import json
import hashlib
import datetime
import requests  # 确保已安装：pip install requests
from pathlib import Path

# 新增：特征库相关路径配置（根据项目实际结构调整）
# 项目根目录（通过当前文件路径向上推导）
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # src的父目录即项目根目录
SIGNATURE_DB_PATH = PROJECT_ROOT / "data" / "signature_db.json"  # 特征库主文件路径
BACKUP_SUFFIX = ".backup"  # 备份文件后缀
LOCAL_UPDATE_FILE = PROJECT_ROOT / "data" / "local_update.json"  # 本地更新包路径
REMOTE_UPDATE_URL = "https://your-update-server.com/signatures"  # 远程更新地址（替换为实际地址）

# 确保数据目录存在
SIGNATURE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


class SignatureManager:
    def __init__(self):
        """初始化特征库管理器，加载本地特征库 - 生产环境核心逻辑"""
        self.db = {}
        self.load_local_db()

    def load_local_db(self):
        """加载本地特征库文件"""
        try:
            if not SIGNATURE_DB_PATH.exists():
                # 首次运行时创建默认特征库
                self.db = self._get_default_db()
                with open(SIGNATURE_DB_PATH, "w", encoding="utf-8") as f:
                    json.dump(self.db, f, indent=2, ensure_ascii=False)
                print(f"初始化默认特征库至：{SIGNATURE_DB_PATH}")
            else:
                with open(SIGNATURE_DB_PATH, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
                print(f"成功加载本地特征库，版本：{self.db.get('update_info', {}).get('version', '未知')}")
        except Exception as e:
            print(f"加载特征库失败：{str(e)}")
            self.db = self._get_default_db()  # 加载默认库

    def _get_default_db(self):
        """获取默认特征库（防止本地库损坏）"""
        return {
            "port_signatures": [],
            "payload_signatures": [],
            "flow_signatures": [],
            "update_info": {"version": "0.0", "last_update": datetime.datetime.now().strftime("%Y-%m-%d")}
        }

    def get_local_hash(self):
        """计算本地特征库的MD5哈希值（用于版本对比）"""
        try:
            with open(SIGNATURE_DB_PATH, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            print(f"计算哈希失败：{str(e)}")
            return ""

    def backup_local_db(self):
        """备份当前特征库 - 生产环境必备"""
        try:
            if not SIGNATURE_DB_PATH.exists():
                print("特征库文件不存在，无需备份")
                return ""
            backup_path = f"{SIGNATURE_DB_PATH}{BACKUP_SUFFIX}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            with open(SIGNATURE_DB_PATH, "r", encoding="utf-8") as src, open(backup_path, "w", encoding="utf-8") as dst:
                json.dump(self.db, dst, indent=2, ensure_ascii=False)
            print(f"特征库已备份至：{backup_path}")
            return backup_path
        except Exception as e:
            print(f"备份特征库失败：{str(e)}")
            return ""

    def update_from_remote(self, timeout=10):
        """从远程服务器更新特征库 - 生产环境可选"""
        if not REMOTE_UPDATE_URL:
            return {"status": "error", "message": "未配置远程更新地址"}
        
        try:
            # 1. 获取本地哈希，检查是否需要更新
            local_hash = self.get_local_hash()
            params = {"local_hash": local_hash, "local_version": self.db.get('update_info', {}).get('version')}
            
            # 2. 请求远程服务器
            response = requests.get(REMOTE_UPDATE_URL, params=params, timeout=timeout)
            if response.status_code != 200:
                return {"status": "error", "message": f"远程服务器返回错误：{response.status_code}"}
            
            update_data = response.json()
            if not update_data.get("need_update", False):
                return {"status": "success", "message": "特征库已是最新版本"}
            
            # 3. 备份本地库
            self.backup_local_db()
            
            # 4. 更新特征库
            new_signatures = update_data["signatures"]
            with open(SIGNATURE_DB_PATH, "w", encoding="utf-8") as f:
                json.dump(new_signatures, f, indent=2, ensure_ascii=False)
            
            # 5. 重新加载库
            self.load_local_db()
            return {
                "status": "success",
                "message": f"特征库更新成功，新版本：{new_signatures.get('update_info', {}).get('version')}",
                "updated_count": len(new_signatures["port_signatures"]) + len(new_signatures["payload_signatures"]) + len(new_signatures["flow_signatures"])
            }
        except requests.exceptions.Timeout:
            return {"status": "error", "message": "连接更新服务器超时"}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "message": "无法连接更新服务器"}
        except Exception as e:
            return {"status": "error", "message": f"远程更新失败：{str(e)}"}

    def update_from_local_file(self, file_path=None):
        """从本地文件更新特征库 - 生产环境核心逻辑"""
        try:
            update_file = file_path or LOCAL_UPDATE_FILE
            if not Path(update_file).exists():
                return {"status": "error", "message": f"本地更新包不存在：{update_file}"}
            
            # 备份本地库
            self.backup_local_db()
            
            # 加载本地更新包
            with open(update_file, "r", encoding="utf-8") as f:
                new_signatures = json.load(f)
            
            # 验证更新包格式
            required_keys = ["port_signatures", "payload_signatures", "flow_signatures", "update_info"]
            if not all(key in new_signatures for key in required_keys):
                return {"status": "error", "message": "更新包格式不合法"}
            
            # 写入新库
            with open(SIGNATURE_DB_PATH, "w", encoding="utf-8") as f:
                json.dump(new_signatures, f, indent=2, ensure_ascii=False)
            
            # 重新加载
            self.load_local_db()
            return {
                "status": "success",
                "message": f"本地更新成功，新版本：{new_signatures.get('update_info', {}).get('version')}"
            }
        except Exception as e:
            return {"status": "error", "message": f"本地更新失败：{str(e)}"}

    def match_signature(self, flow_data):
        """匹配流量数据与特征库，返回匹配的攻击特征 - 生产环境核心逻辑"""
        matches = []
        if not flow_data:
            return matches
        
        # 1. 端口特征匹配
        src_port = flow_data.get("Src Port")
        dst_port = flow_data.get("Dst Port")
        for sig in self.db.get("port_signatures", []):
            if sig["port"] in [src_port, dst_port]:
                matches.append({
                    "type": "port",
                    "id": sig["id"],
                    "risk": sig["risk"],
                    "attack_type": sig["attack_type"],
                    "description": sig["description"],
                    "matched_port": src_port if sig["port"] == src_port else dst_port
                })
        
        # 2. 载荷特征匹配（需流量数据包含Payload字段）
        payload = str(flow_data.get("Payload", "")).lower()
        for sig in self.db.get("payload_signatures", []):
            if sig["pattern"].lower() in payload:
                matches.append({
                    "type": "payload",
                    "id": sig["id"],
                    "risk": sig["risk"],
                    "attack_type": sig["attack_type"],
                    "description": sig["description"],
                    "matched_pattern": sig["pattern"]
                })
        
        # 3. 流量特征匹配
        flow_duration = flow_data.get("Flow Duration", 0)
        packet_count = flow_data.get("Total Fwd Packets", 0) + flow_data.get("Total Bwd Packets", 0)
        ttl_variance = flow_data.get("TTL Variance", 0)
        for sig in self.db.get("flow_signatures", []):
            if sig.get("duration_threshold_ms") and flow_duration > sig["duration_threshold_ms"]:
                matches.append({
                    "type": "flow",
                    "id": sig["id"],
                    "risk": sig["risk"],
                    "attack_type": sig["attack_type"],
                    "description": sig["description"],
                    "matched_value": f"流量时长{flow_duration}ms > 阈值{sig['duration_threshold_ms']}ms"
                })
            elif sig.get("packet_count_threshold") and packet_count > sig["packet_count_threshold"]:
                matches.append({
                    "type": "flow",
                    "id": sig["id"],
                    "risk": sig["risk"],
                    "attack_type": sig["attack_type"],
                    "description": sig["description"],
                    "matched_value": f"数据包数{packet_count} > 阈值{sig['packet_count_threshold']}"
                })
            elif sig.get("ttl_variance_threshold") and ttl_variance > sig["ttl_variance_threshold"]:
                matches.append({
                    "type": "flow",
                    "id": sig["id"],
                    "risk": sig["risk"],
                    "attack_type": sig["attack_type"],
                    "description": sig["description"],
                    "matched_value": f"TTL波动{ttl_variance} > 阈值{sig['ttl_variance_threshold']}"
                })
        
        # 按风险等级排序（critical > high > medium > low）
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches.sort(key=lambda x: risk_order.get(x["risk"], 99))
        return matches