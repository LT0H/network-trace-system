mod ip_counter;

use clap::Parser;
use pcap::Capture;
use serde::Serialize;
use serde_json::to_writer;
use std::error::Error;
use std::fs::File;
use std::collections::{HashMap, HashSet};

// 定义命令行参数
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "输入的pcap文件路径")]
    f: String,

    #[arg(short, long, help = "输出的JSON文件路径")]
    o: String,
}

// 定义分析结果结构（根据实际需求调整）
#[derive(Debug, Serialize)]
struct AnalysisResult {
    total_packets: u32,
    protocol_distribution: HashMap<String, u32>,
    ip_addresses: HashSet<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    // 解析命令行参数
    let args = Args::parse();
    let pcap_path = &args.f;
    let output_path = &args.o;

    // 打开pcap文件（Offline表示读取本地文件）
    let mut cap = Capture::from_file(pcap_path)?;

    // 分析pcap文件（示例逻辑，根据需求实现）
    let mut result = AnalysisResult {
        total_packets: 0,
        protocol_distribution: HashMap::new(),
        ip_addresses: HashSet::new(),
    };

    // 🔥 修正：用迭代器遍历数据包（pcap 2.4.0 推荐用法）
    // cap.iter() 返回迭代器，元素类型为 Result<Packet<'_>, Error>
    for packet_result in cap.iter() {
        // 解包 Result：失败则返回错误，成功则获取 Packet
        let packet = packet_result?;
        result.total_packets += 1;

        // 解析以太网帧（简化示例）
        if packet.len() >= 14 {
            let eth_type = &packet[12..14];
            let proto = match eth_type {
                [0x08, 0x00] => "IPv4",
                [0x08, 0x06] => "ARP",
                [0x86, 0xDD] => "IPv6",
                _ => "Other",
            };
            *result.protocol_distribution.entry(proto.to_string()).or_insert(0) += 1;
        }

        // （可选）提取IP地址（以IPv4为例）
        if packet.len() >= 34 { // 以太网帧（14字节）+ IPv4头（至少20字节）
            let ip_header = &packet[14..34];
            let src_ip = format!(
                "{}.{}.{}.{}",
                ip_header[12], ip_header[13], ip_header[14], ip_header[15]
            );
            result.ip_addresses.insert(src_ip);
        }
    }

    // 输出JSON结果
    let output_file = File::create(output_path)?;
    to_writer(output_file, &result)?;

    println!("分析完成！结果已保存到：{}", output_path);
    println!("统计信息：");
    println!("- 总数据包数：{}", result.total_packets);
    println!("- 协议分布：{:?}", result.protocol_distribution);
    println!("- 涉及IP地址数：{}", result.ip_addresses.len());

    Ok(())
}