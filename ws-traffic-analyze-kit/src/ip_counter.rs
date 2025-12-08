// ip_counter.rs
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::env;
use csv::Reader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub(crate) fn ip_counter() -> Result<(), Box<dyn Error>> {
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("请提供CSV文件路径作为参数（格式：common_ip.exe <csv_path>）".into());
    }
    let csv_path = &args[1];

    // 使用命令行参数指定的CSV路径
    let mut csv_reader = Reader::from_path(csv_path)
        .map_err(|e| format!("无法打开CSV文件: {} - 错误: {}", csv_path, e))?;
    let mut ip_user_map: HashMap<String, HashSet<String>> = HashMap::new();

    let whitelist_ip = vec!["219.217.200.201".to_string()];

    for (row_idx, record) in csv_reader.records().enumerate() {
        let record = record.map_err(|e| format!("第 {} 行解析失败: {}", row_idx + 1, e))?;
        
        // 安全获取IP和用户列，避免unwrap崩溃
        let ip = record.get(1)
            .ok_or(format!("第 {} 行缺少IP列（索引1）", row_idx + 1))?
            .to_string();
        let user = record.get(2)
            .ok_or(format!("第 {} 行缺少用户列（索引2）", row_idx + 1))?
            .to_string();
        
        ip_user_map.entry(ip).or_insert_with(HashSet::new).insert(user);
    }

    let mut sorted_ips: Vec<_> = ip_user_map.iter().collect();
    sorted_ips.sort_by_key(|(_, users)| std::cmp::Reverse(users.len()));

    let mut output_buffer = Vec::new();

    for (ip, users) in sorted_ips {
        if whitelist_ip.contains(ip) {
            continue;
        }
        if users.len() > 1 {
            writeln!(output_buffer, "IP: {} ({})", ip, users.len())?;
            writeln!(output_buffer, "Users: [{}]", users.iter().map(String::as_str).collect::<Vec<_>>().join(", "))?;
            writeln!(output_buffer, "")?;
        }
    }

    let mut file = BufWriter::new(File::create("ip_counts.txt")
        .map_err(|e| format!("无法创建输出文件 ip_counts.txt: {}", e))?);
    file.write_all(&output_buffer)?;

    Ok(())
}