#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP地址地理位置查询模块
"""

import os
import sys
import logging
import struct
import socket
from datetime import datetime

class IPGeolocation:
    """
    IP地址地理位置查询类，用于查询IP地址的地理位置信息
    支持qqwry.dat数据库格式
    """
    
    def __init__(self, qqwry_path):
        """
        初始化IPGeolocation实例
        
        Args:
            qqwry_path (str): qqwry.dat数据库文件路径
        """
        self.logger = logging.getLogger(__name__)
        self.qqwry_path = qqwry_path
        self.db = None
        self.db_size = 0
        self.ip_start = 0
        self.ip_end = 0
        self.ip_count = 0
        
        # 加载数据库
        self._load_db()
        
        self.logger.info("IP地理位置查询模块已初始化")
    
    def _load_db(self):
        """
        加载qqwry.dat数据库
        """
        try:
            # 检查数据库文件是否存在
            if not os.path.exists(self.qqwry_path):
                self.logger.error(f"数据库文件不存在: {self.qqwry_path}")
                raise FileNotFoundError(f"数据库文件不存在: {self.qqwry_path}")
            
            # 获取数据库文件大小
            self.db_size = os.path.getsize(self.qqwry_path)
            
            # 打开数据库文件
            with open(self.qqwry_path, 'rb') as f:
                self.db = f.read()
            
            # 读取索引信息
            # 前8字节是索引的起始和结束位置
            self.ip_start, self.ip_end = struct.unpack('II', self.db[:8])
            
            # 计算IP记录数量
            self.ip_count = (self.ip_end - self.ip_start) // 7 + 1
            
            self.logger.info(f"数据库加载成功: 文件大小={self.db_size}字节, IP记录数={self.ip_count}")
            
        except Exception as e:
            self.logger.error(f"加载数据库失败: {e}")
            self.db = None
            raise
    
    def query(self, ip):
        """
        查询IP地址的地理位置
        
        Args:
            ip (str): IP地址字符串
            
        Returns:
            str: 地理位置信息
        """
        if not self.db:
            raise RuntimeError("数据库未加载")
        
        # 验证IP地址格式
        try:
            ip_bytes = socket.inet_aton(ip)
            ip_int = struct.unpack('!I', ip_bytes)[0]
        except Exception as e:
            self.logger.error(f"无效的IP地址: {ip}")
            raise ValueError(f"无效的IP地址: {ip}")
        
        # 二分查找IP地址
        left = 0
        right = self.ip_count - 1
        
        while left <= right:
            mid = (left + right) // 2
            pos = self.ip_start + mid * 7
            
            # 读取IP地址
            cur_ip = struct.unpack('!I', self.db[pos:pos+4])[0]
            
            if ip_int < cur_ip:
                right = mid - 1
            else:
                left = mid + 1
        
        # 找到匹配的记录
        if right < 0:
            return "未知"
        
        # 获取记录位置
        pos = self.ip_start + right * 7
        
        # 读取IP地址和偏移量
        ip_start, offset = struct.unpack('!IH', self.db[pos:pos+6])
        country_pos = self.ip_start + offset
        
        # 读取国家信息
        country, area = self._read_location(country_pos)
        
        # 格式化结果
        result = country
        if area and area != country:
            result = f"{country} {area}"
        
        return result
    
    def _read_location(self, pos):
        """
        读取位置信息
        
        Args:
            pos (int): 位置偏移量
            
        Returns:
            tuple: (国家, 地区)
        """
        # 读取第一个字节
        flag = self.db[pos]
        
        if flag == 1:
            # 国家信息是指向另一个位置的指针
            country_offset = struct.unpack('!I', self.db[pos+1:pos+5])[0] & 0x00FFFFFF
            country, area = self._read_location(country_offset)
        elif flag == 2:
            # 国家信息是指向另一个位置的指针
            country_offset = struct.unpack('!I', self.db[pos+1:pos+5])[0] & 0x00FFFFFF
            country, _ = self._read_location(country_offset)
            
            # 读取地区信息
            area_pos = pos + 5
            area_flag = self.db[area_pos]
            
            if area_flag == 1 or area_flag == 2:
                area_offset = struct.unpack('!I', self.db[area_pos+1:area_pos+5])[0] & 0x00FFFFFF
                _, area = self._read_location(area_offset)
            else:
                area = self._read_string(area_pos)
        else:
            # 国家信息是直接存储的字符串
            country = self._read_string(pos)
            
            # 读取地区信息
            area_pos = pos + len(country) + 1
            area_flag = self.db[area_pos]
            
            if area_flag == 1 or area_flag == 2:
                area_offset = struct.unpack('!I', self.db[area_pos+1:area_pos+5])[0] & 0x00FFFFFF
                _, area = self._read_location(area_offset)
            else:
                area = self._read_string(area_pos)
        
        return country, area
    
    def _read_string(self, pos):
        """
        读取字符串
        
        Args:
            pos (int): 字符串起始位置
            
        Returns:
            str: 解码后的字符串
        """
        # 查找字符串结束位置
        end = pos
        while end < self.db_size and self.db[end] != 0:
            end += 1
        
        # 提取字符串并解码
        if pos < end:
            try:
                # 尝试使用GBK解码（qqwry.dat通常使用GBK编码）
                return self.db[pos:end].decode('gbk')
            except UnicodeDecodeError:
                # 如果GBK解码失败，尝试使用UTF-8
                try:
                    return self.db[pos:end].decode('utf-8')
                except UnicodeDecodeError:
                    # 如果都失败，返回十六进制表示
                    return self.db[pos:end].hex()
        
        return ""
    
    def batch_query(self, ip_list):
        """
        批量查询IP地址
        
        Args:
            ip_list (list): IP地址列表
            
        Returns:
            dict: {ip: 地理位置}的字典
        """
        results = {}
        
        for ip in ip_list:
            try:
                results[ip] = self.query(ip)
            except Exception as e:
                self.logger.error(f"查询IP失败: {ip}, 错误={e}")
                results[ip] = "查询失败"
        
        return results
    
    def get_db_info(self):
        """
        获取数据库信息
        
        Returns:
            dict: 数据库信息
        """
        if not self.db:
            return {"error": "数据库未加载"}
        
        return {
            "file_path": self.qqwry_path,
            "file_size": self.db_size,
            "ip_count": self.ip_count,
            "loaded_at": datetime.now().isoformat()
        }
    
    def reload_db(self):
        """
        重新加载数据库
        """
        self.logger.info("重新加载数据库")
        self._load_db()
    
    def __del__(self):
        """
        析构函数
        """
        # 清理资源
        self.db = None
        self.logger.info("IP地理位置查询模块已关闭")