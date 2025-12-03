import os
import struct
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class QQWryIPLocator:
    """纯真IP库解析器，用于IP地址溯源"""
    
    def __init__(self):
        # 纯真IP库文件存放位置
        self.db_path = os.path.join(settings.BASE_DIR, 'data', 'qqwry.dat')
        self.f = None
        self.start_offset = 0
        self.end_offset = 0
        self.init_db()
    
    def init_db(self):
        """初始化IP数据库"""
        try:
            if not os.path.exists(self.db_path):
                logger.warning(f"纯真IP库文件不存在: {self.db_path}，请将qqwry.dat放在该位置")
                return
                
            self.f = open(self.db_path, 'rb')
            # 读取文件头，获取开始和结束偏移量
            self.start_offset = struct.unpack('<I', self.f.read(4))[0]
            self.end_offset = struct.unpack('<I', self.f.read(4))[0]
            logger.info(f"纯真IP库加载成功，记录数量: {(self.end_offset - self.start_offset) // 7 + 1}")
        except Exception as e:
            logger.error(f"初始化IP数据库失败: {e}")
            self.f = None
    
    def query(self, ip):
        """查询IP地址对应的地理位置"""
        if not self.f:
            return {"ip": ip, "country": "未知", "city": "未知", "error": "IP数据库未加载"}
            
        try:
            # 将IP地址转换为整数
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            # 二分查找
            left = 0
            right = (self.end_offset - self.start_offset) // 7
            
            while left <= right:
                mid = (left + right) // 2
                offset = self.start_offset + mid * 7
                self.f.seek(offset)
                
                # 读取IP和偏移量
                cur_ip = struct.unpack('<I', self.f.read(4))[0]
                record_offset = struct.unpack('<I', self.f.read(3) + b'\x00')[0]
                
                if ip_int < cur_ip:
                    right = mid - 1
                else:
                    left = mid + 1
                    result_offset = record_offset
            
            # 读取查询结果
            self.f.seek(result_offset)
            flag = struct.unpack('B', self.f.read(1))[0]
            
            # 读取国家
            if flag == 1:  # 国家使用偏移量
                country_offset = struct.unpack('<I', self.f.read(3) + b'\x00')[0]
                self.f.seek(country_offset)
                flag = struct.unpack('B', self.f.read(1))[0]
                
                if flag == 2:  # 再次偏移
                    country_offset = struct.unpack('<I', self.f.read(3) + b'\x00')[0]
                    self.f.seek(country_offset)
                
                country = self._read_string()
            else:  # 直接读取国家
                self.f.seek(result_offset + 1)
                country = self._read_string()
            
            # 读取城市
            if flag in (1, 2):
                flag = struct.unpack('B', self.f.read(1))[0]
                
                if flag == 2:  # 城市使用偏移量
                    city_offset = struct.unpack('<I', self.f.read(3) + b'\x00')[0]
                    self.f.seek(city_offset)
                else:  # 直接读取城市
                    city_offset = self.f.tell() - 1
                
                city = self._read_string()
            else:
                city = self._read_string()
            
            return {
                "ip": ip,
                "country": country.strip(),
                "city": city.strip()
            }
            
        except Exception as e:
            logger.error(f"IP查询失败: {e}")
            return {"ip": ip, "country": "未知", "city": "未知", "error": str(e)}
    
    def _read_string(self):
        """从当前位置读取字符串"""
        result = []
        while True:
            b = self.f.read(1)
            if b == b'\x00' or not b:
                break
            result.append(b)
        return b''.join(result).decode('gbk', errors='replace')
    
    def close(self):
        """关闭数据库文件"""
        if self.f:
            self.f.close()
            self.f = None