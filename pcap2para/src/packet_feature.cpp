#include "packet_feature.h"
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <boost/regex.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cstring>
#include "progressbar.hpp"

// 全局配置：支持HTTP(80)、HTTPS(443)、常用HTTP代理端口(8080)
const std::set<uint16_t> SUPPORTED_PORTS = {80, 443, 8080};

// ===================== 补充缺失函数1：get_packet_count（匹配pcap2rsa调用签名） =====================
int get_packet_count(const std::string& pcap_path) {
    try {
        pcpp::PcapFileReaderDevice reader(pcap_path.c_str());
        if (!reader.open()) {
            std::cerr << "❌ 无法打开PCAP文件：" << pcap_path << std::endl;
            return -1;
        }

        uint64_t count = 0;
        pcpp::RawPacket raw_packet;
        while (reader.getNextPacket(raw_packet)) {
            count++;
        }
        reader.close();
        return static_cast<int>(count);
    } catch (...) {
        std::cerr << "❌ 统计数据包数量失败：" << pcap_path << std::endl;
        return -1;
    }
}

// ===================== 补充缺失函数2：get_regexes（匹配pcap2rsa调用签名） =====================
std::vector<boost::regex> get_regexes(const std::string& params_str) {
    std::vector<boost::regex> regexes;
    std::vector<std::string> parameters;
    
    // 分割参数字符串（按逗号/空格分割）
    std::stringstream ss(params_str);
    std::string param;
    while (std::getline(ss, param, ',')) {
        // 去除首尾空格
        param.erase(0, param.find_first_not_of(" \t"));
        param.erase(param.find_last_not_of(" \t") + 1);
        if (!param.empty()) {
            parameters.push_back(param);
        }
    }

    // 编译正则表达式（支持URL/POST/JSON参数匹配）
    for (const auto& p : parameters) {
        std::string pattern = R"((?:\?|&|=|":|:\s*")" + p + R"((?:=|":|:\s*")([^&"\\]+))";
        regexes.emplace_back(pattern, boost::regex::icase);
    }

    return regexes;
}

// ===================== 补充缺失函数3：match_regex_from_reader（匹配pcap2rsa调用签名） =====================
int match_regex_from_reader(bool is_http, std::ofstream& outfile, const std::string& pcap_path, int total_packets, const std::vector<boost::regex>& regexes) {
    try {
        // 初始化PCAP读取器
        pcpp::PcapFileReaderDevice reader(pcap_path.c_str());
        if (!reader.open()) {
            std::cerr << "❌ 无法打开PCAP文件：" << pcap_path << std::endl;
            return -1;
        }

        // 初始化进度条
        progressbar bar(total_packets);
        pcpp::RawPacket raw_packet;
        int processed = 0;
        int matched_count = 0;

        // 遍历所有数据包
        while (reader.getNextPacket(raw_packet)) {
            processed++;
            bar.update();

            // 构造Packet对象
            pcpp::Packet parsed_packet(&raw_packet, true);

            // 检查TCP层
            const pcpp::TcpLayer* tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();
            if (!tcp_layer) continue;

            // 多端口过滤
            uint16_t src_port = tcp_layer->getSrcPort();
            uint16_t dst_port = tcp_layer->getDstPort();
            if (!(SUPPORTED_PORTS.count(src_port) || SUPPORTED_PORTS.count(dst_port))) continue;

            // 提取HTTP payload
            std::string payload;
            bool has_payload = false;

            // 解析HTTP请求
            if (parsed_packet.isPacketOfType(pcpp::HTTPRequest)) {
                const pcpp::HttpRequestLayer* req_layer = parsed_packet.getLayerOfType<pcpp::HttpRequestLayer>();
                if (req_layer) {
                    const uint8_t* payload_ptr = req_layer->getLayerPayload();
                    size_t payload_size = req_layer->getLayerPayloadSize();
                    if (payload_ptr && payload_size > 0) {
                        payload = std::string(reinterpret_cast<const char*>(payload_ptr), payload_size);
                        has_payload = true;
                    }
                }
            }
            // 解析HTTP响应
            else if (parsed_packet.isPacketOfType(pcpp::HTTPResponse)) {
                const pcpp::HttpResponseLayer* resp_layer = parsed_packet.getLayerOfType<pcpp::HttpResponseLayer>();
                if (resp_layer) {
                    const uint8_t* payload_ptr = resp_layer->getLayerPayload();
                    size_t payload_size = resp_layer->getLayerPayloadSize();
                    if (payload_ptr && payload_size > 0) {
                        payload = std::string(reinterpret_cast<const char*>(payload_ptr), payload_size);
                        has_payload = true;
                    }
                }
            }

            // 匹配正则表达式
            if (has_payload && !payload.empty()) {
                for (const auto& re : regexes) {
                    boost::sregex_iterator it(payload.begin(), payload.end(), re);
                    boost::sregex_iterator end;

                    for (; it != end; ++it) {
                        if ((*it).size() > 1) {
                            outfile << (*it)[1].str() << std::endl;
                            matched_count++;
                        }
                    }
                }
            }
        }

        reader.close();
        std::cout << "\n✅ 解析完成：处理数据包 " << processed << " 个，匹配参数 " << matched_count << " 个" << std::endl;
        return matched_count;

    } catch (const std::exception& e) {
        std::cerr << "❌ 解析PCAP失败：" << e.what() << std::endl;
        return -1;
    }
}

// ===================== 原有核心功能函数（保留） =====================
// 提取HTTP原始payload
std::string get_http_full_payload(const pcpp::HttpRequestLayer* req_layer) {
    if (!req_layer) return "";
    const uint8_t* payload_ptr = req_layer->getLayerPayload();
    size_t payload_size = req_layer->getLayerPayloadSize();
    if (!payload_ptr || payload_size == 0) return "";
    return std::string(reinterpret_cast<const char*>(payload_ptr), payload_size);
}

// 解析HTTP数据包
bool parse_http_packet(const pcpp::Packet& parsed_packet, std::string& payload) {
    // HTTP请求
    if (parsed_packet.isPacketOfType(pcpp::HTTPRequest)) {
        const pcpp::HttpRequestLayer* req_layer = parsed_packet.getLayerOfType<pcpp::HttpRequestLayer>();
        payload = get_http_full_payload(req_layer);
        return !payload.empty();
    }
    // HTTP响应
    if (parsed_packet.isPacketOfType(pcpp::HTTPResponse)) {
        const pcpp::HttpResponseLayer* resp_layer = parsed_packet.getLayerOfType<pcpp::HttpResponseLayer>();
        if (!resp_layer) return false;
        const uint8_t* payload_ptr = resp_layer->getLayerPayload();
        size_t payload_size = resp_layer->getLayerPayloadSize();
        if (payload_ptr && payload_size > 0) {
            payload = std::string(reinterpret_cast<const char*>(payload_ptr), payload_size);
            return true;
        }
    }
    return false;
}

// 多端口过滤
bool is_supported_port(const pcpp::TcpLayer* tcp_layer) {
    if (!tcp_layer) return false;
    uint16_t src_port = tcp_layer->getSrcPort();
    uint16_t dst_port = tcp_layer->getDstPort();
    return SUPPORTED_PORTS.count(src_port) || SUPPORTED_PORTS.count(dst_port);
}

// 统计PCAP数据包总数
uint64_t count_pcap_packets(const std::string& pcap_path) {
    pcpp::PcapFileReaderDevice reader(pcap_path.c_str());
    if (!reader.open()) {
        throw std::runtime_error("Failed to open PCAP file for counting: " + pcap_path);
    }
    uint64_t count = 0;
    pcpp::RawPacket raw_packet;
    while (reader.getNextPacket(raw_packet)) {
        count++;
    }
    reader.close();
    return count;
}

// 核心解析函数
std::map<std::string, std::vector<std::string>> extract_features_from_pcap(const std::string& pcap_path, const std::vector<std::string>& parameters) {
    std::map<std::string, std::vector<std::string>> feature_map;

    pcpp::PcapFileReaderDevice reader(pcap_path.c_str());
    if (!reader.open()) {
        throw std::runtime_error("Failed to open PCAP file: " + pcap_path);
    }

    uint64_t total_packets = count_pcap_packets(pcap_path);
    if (total_packets == 0) {
        reader.close();
        return feature_map;
    }

    progressbar bar(static_cast<int>(total_packets));
    pcpp::RawPacket raw_packet;
    uint64_t processed = 0;

    // 编译正则表达式
    std::vector<boost::regex> regexes;
    for (const auto& param : parameters) {
        std::string pattern = R"((?:\?|&|=|":|:\s*")" + param + R"((?:=|":|:\s*")([^&"\\]+))";
        regexes.emplace_back(pattern, boost::regex::icase);
    }

    // 遍历数据包
    while (reader.getNextPacket(raw_packet)) {
        processed++;
        bar.update();

        pcpp::Packet parsed_packet(&raw_packet, true);
        const pcpp::TcpLayer* tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();
        if (!tcp_layer || !is_supported_port(tcp_layer)) continue;

        std::string payload;
        if (!parse_http_packet(parsed_packet, payload)) continue;

        // 匹配参数
        for (size_t i = 0; i < parameters.size(); ++i) {
            const std::string& param = parameters[i];
            const boost::regex& re = regexes[i];

            boost::sregex_iterator it(payload.begin(), payload.end(), re);
            boost::sregex_iterator end;

            for (; it != end; ++it) {
                if ((*it).size() > 1) {
                    feature_map[param].push_back((*it)[1].str());
                }
            }
        }
    }

    reader.close();
    std::cout << "\n✅ PCAP解析完成，处理数据包数：" << processed << std::endl;
    return feature_map;
}

// 保存结果到文件
void save_features_to_file(const std::map<std::string, std::vector<std::string>>& feature_map, const std::string& output_path) {
    std::ofstream outfile(output_path, std::ios::out | std::ios::trunc);
    if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open output file: " + output_path);
    }

    outfile << "========================================" << std::endl;
    outfile << "PCAP Parameter Extraction Result" << std::endl;
    outfile << "========================================" << std::endl;

    for (const auto& [param, values] : feature_map) {
        outfile << "\nParameter: " << param << std::endl;
        outfile << "----------------------------------------" << std::endl;
        if (values.empty()) {
            outfile << "No values found" << std::endl;
            continue;
        }

        std::set<std::string> unique_values(values.begin(), values.end());
        for (const auto& val : unique_values) {
            outfile << val << std::endl;
        }
        outfile << "Total unique values: " << unique_values.size() << std::endl;
    }

    outfile.close();
}