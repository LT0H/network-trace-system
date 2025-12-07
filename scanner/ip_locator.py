import struct
import logging

logger = logging.getLogger(__name__)

class IPLocator:
    """基于qqwry.dat的IP地址定位工具"""
    def __init__(self, qqwry_path):
        self.qqwry_path = qqwry_path
        self.f = None
        self.index_start = 0
        self.index_end = 0
        self.total_index = 0
        
        try:
            self._load_qqwry()
        except Exception as e:
            logger.error(f"加载qqwry.dat失败: {e}")
    
    def _load_qqwry(self):
        """加载qqwry.dat文件"""
        self.f = open(self.qqwry_path, 'rb')
        
        # 读取索引区范围
        self.index_start, = struct.unpack('I', self.f.read(4))
        self.index_end, = struct.unpack('I', self.f.read(4))
        self.total_index = (self.index_end - self.index_start) // 7 + 1
    
    def query(self, ip):
        """查询IP地址对应的地理位置"""
        if not self.f:
            return {"country": "未知", "area": "未知"}
            
        try:
            # 将IP转换为整数
            ip_parts = list(map(int, ip.split('.')))
            ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
            
            # 二分查找
            left = 0
            right = self.total_index
            
            while left <= right:
                mid = (left + right) // 2
                self.f.seek(self.index_start + mid * 7)
                
                # 读取起始IP
                start_ip, = struct.unpack('I', self.f.read(4))
                # 读取偏移量
                offset, = struct.unpack('I', b'\x00' + self.f.read(3))
                
                if ip_int < start_ip:
                    right = mid - 1
                else:
                    left = mid + 1
                    found_offset = offset
            
            # 查找结束，处理结果
            self.f.seek(found_offset)
            # 读取结束IP
            end_ip, = struct.unpack('I', self.f.read(4))
            
            if ip_int > end_ip:
                return {"country": "未知", "area": "未知"}
            
            # 读取国家信息
            mode = self.f.read(1)
            if mode == b'\x01':  # 国家信息是偏移量
                country_offset, = struct.unpack('I', b'\x00' + self.f.read(3))
                self.f.seek(country_offset)
                mode = self.f.read(1)
                
            if mode == b'\x02':  # 再次指向偏移量
                country_offset, = struct.unpack('I', b'\x00' + self.f.read(3))
                self.f.seek(country_offset)
            country = self._read_string()
            
            # 读取地区信息
            mode = self.f.read(1)
            if mode == b'\x01' or mode == b'\x02':
                area_offset, = struct.unpack('I', b'\x00' + self.f.read(3))
                self.f.seek(area_offset)
            else:
                self.f.seek(-1, 1)  # 回退一个字节
            area = self._read_string()
            
            return {"country": country, "area": area}
            
        except Exception as e:
            logger.error(f"IP查询失败: {e}")
            return {"country": "未知", "area": "未知"}
    
    def _read_string(self):
        """读取字符串直到遇到0x00"""
        s = b''
        while True:
            c = self.f.read(1)
            if c == b'\x00' or not c:
                break
            s += c
        try:
            return s.decode('gbk')
        except UnicodeDecodeError:
            return s.decode('utf-8', errors='replace')
    
    def close(self):
        """关闭文件"""
        if self.f:
            self.f.close()
            self.f = None