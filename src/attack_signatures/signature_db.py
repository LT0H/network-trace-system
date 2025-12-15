import sqlite3
import json
from datetime import datetime
import hashlib
from pathlib import Path

# 数据库路径配置
DB_PATH = Path(__file__).parent / "attack_signatures.db"

class SignatureDatabase:
    def __init__(self):
        """初始化特征库数据库"""
        self.conn = sqlite3.connect(str(DB_PATH))
        self.create_tables()
    
    def create_tables(self):
        """创建数据库表结构"""
        cursor = self.conn.cursor()
        
        # 攻击特征表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,  # port, payload, flow
            pattern TEXT NOT NULL,  # 特征模式
            attack_type TEXT NOT NULL,  # 攻击类型
            risk TEXT NOT NULL,  # critical, high, medium, low
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # 设备指纹表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            os_type TEXT,
            open_ports TEXT,  # JSON格式存储
            service_versions TEXT,  # JSON格式存储
            ttl_range TEXT,
            fingerprint_hash TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # 威胁情报表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL UNIQUE,  # IP, 域名, 哈希等
            indicator_type TEXT NOT NULL,
            source TEXT,  # 情报来源
            description TEXT,
            severity TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            mitre_attack_ref TEXT  # MITRE ATT&CK参考
        )
        ''')
        
        # 特征库版本表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS signature_version (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            hash_value TEXT NOT NULL,
            update_source TEXT
        )
        ''')
        
        self.conn.commit()
    
    def insert_signature(self, signature):
        """插入新的攻击特征"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO attack_signatures (type, pattern, attack_type, risk, description)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            signature['type'],
            signature['pattern'],
            signature['attack_type'],
            signature['risk'],
            signature.get('description', '')
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_signatures_by_type(self, sig_type):
        """按类型获取特征"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT * FROM attack_signatures WHERE type = ?
        ''', (sig_type,))
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def insert_fingerprint(self, fingerprint):
        """插入设备指纹"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT OR REPLACE INTO device_fingerprints 
        (ip_address, os_type, open_ports, service_versions, ttl_range, fingerprint_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            fingerprint['ip_address'],
            fingerprint.get('os_type'),
            json.dumps(fingerprint.get('open_ports', {})),
            json.dumps(fingerprint.get('service_versions', {})),
            fingerprint.get('ttl_range'),
            fingerprint.get('hash')
        ))
        self.conn.commit()
    
    def close(self):
        """关闭数据库连接"""
        self.conn.close()