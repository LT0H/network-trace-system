use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::env;
use csv::Reader;
use std::fs::File;
use std::io::{BufWriter, Write};
use chrono;
use std::time::SystemTime;

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

    // 解析CSV并构建IP-用户映射
    for (row_idx, record) in csv_reader.records().enumerate() {
        let record = record.map_err(|e| format!("第 {} 行解析失败: {}", row_idx + 1, e))?;
        let ip = record.get(1)
            .ok_or(format!("第 {} 行缺少IP列（索引1）", row_idx + 1))?
            .to_string();
        let user = record.get(2)
            .ok_or(format!("第 {} 行缺少用户列（索引2）", row_idx + 1))?
            .to_string();
        ip_user_map.entry(ip).or_insert_with(HashSet::new).insert(user);
    }

    // 数据统计
    let total_ip_count = ip_user_map.len();
    let filtered_ip_count = ip_user_map.iter()
        .filter(|(ip, _)| !whitelist_ip.contains(ip))
        .count();
    let multi_user_ip_count = ip_user_map.iter()
        .filter(|(ip, users)| !whitelist_ip.contains(ip) && users.len() > 1)
        .count();
    let total_user_count: usize = ip_user_map.values().map(|users| users.len()).sum();

    // 按用户数倒序排序
    let mut sorted_ips: Vec<_> = ip_user_map.iter().collect();
    sorted_ips.sort_by_key(|(_, users)| std::cmp::Reverse(users.len()));

    // 构建输出内容
    let mut output_buffer = Vec::new();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(now as i64, 0)
        .expect("Failed to convert timestamp to datetime");
    let formatted_time = dt.format("%Y-%m-%d %H:%M:%S").to_string();

    // 1. 表头说明
    let line_80 = "=".repeat(80);
    writeln!(output_buffer, "{}", line_80)?;
    writeln!(output_buffer, "📊 多用户IP分析报告（生成时间：{}）", formatted_time)?;
    writeln!(output_buffer, "{}", line_80)?;
    
    writeln!(output_buffer, "【统计摘要】")?;
    writeln!(output_buffer, "• 总IP数：{} 个", total_ip_count)?;
    writeln!(output_buffer, "• 过滤白名单后IP数：{} 个", filtered_ip_count)?;
    writeln!(output_buffer, "• 多用户IP数（关联用户>1）：{} 个", multi_user_ip_count)?;
    writeln!(output_buffer, "• 涉及总用户数：{} 个", total_user_count)?;
    writeln!(output_buffer, "• 白名单IP：{:?}", whitelist_ip)?;
    writeln!(output_buffer, "• 分析文件：{}", csv_path)?;
    writeln!(output_buffer, "\n【说明】仅展示关联用户数>1的IP（单用户IP已过滤）")?;
    
    let line_dash_80 = "-".repeat(80);
    writeln!(output_buffer, "{}", line_dash_80)?;

    // 2. TOP5 多用户IP
    writeln!(output_buffer, "\n🏆 TOP 5 关联用户最多的IP：")?;
    for (idx, (ip, users)) in sorted_ips.iter().take(5).enumerate() {
        if whitelist_ip.contains(ip) || users.len() <= 1 {
            continue;
        }
        writeln!(output_buffer, "  {}. IP: {} → 关联用户数：{} 个", idx + 1, ip, users.len())?;
    }
    writeln!(output_buffer, "{}", line_dash_80)?;

    // 3. 详细IP列表
    writeln!(output_buffer, "\n📋 多用户IP详细信息：")?;
    let line_dash_50 = "-".repeat(50);
    for (ip, users) in sorted_ips {
        if whitelist_ip.contains(ip) {
            continue;
        }
        if users.len() <= 1 {
            continue;
        }

        // IP基本信息
        writeln!(output_buffer, "\n【IP：{}】", ip)?;
        writeln!(output_buffer, "  关联用户数：{} 个", users.len())?;
        writeln!(output_buffer, "  用户ID列表（每10个一行）：")?;

        // 转换为&str后join
        let user_list: Vec<&str> = users.iter().map(|s| s.as_str()).collect();
        for chunk in user_list.chunks(10) {
            writeln!(output_buffer, "    {}", chunk.join(", "))?;
        }
        writeln!(output_buffer, "{}", line_dash_50)?;
    }

    // 4. 结尾备注
    let end_line = format!("\n{}", line_80);
    writeln!(output_buffer, "{}", end_line)?;
    writeln!(output_buffer, "📝 报告说明：")?;
    writeln!(output_buffer, "1. 白名单IP已自动过滤，不参与统计")?;
    writeln!(output_buffer, "2. 仅展示关联2个及以上用户的IP，单用户IP已隐藏")?;
    writeln!(output_buffer, "3. 用户ID按原始CSV数据展示，未去重（同一IP下用户唯一）")?;
    writeln!(output_buffer, "{}", line_80)?;

    // ========== 关键修复：指定结果文件绝对路径 ==========
    let output_path = r"C:\Users\z1395\network_trace_system\ws-traffic-analyze-kit\ip_counts.txt";
    // 确保目录存在
    std::fs::create_dir_all(std::path::Path::new(output_path).parent().unwrap())?;
    let mut file = BufWriter::new(File::create(output_path)
        .map_err(|e| format!("无法创建输出文件{}：{}", output_path, e))?);
    // 写入UTF-8 BOM，兼容Windows记事本
    file.write_all(&[0xEF, 0xBB, 0xBF])?;
    file.write_all(&output_buffer)?;

    println!("✅ 分析完成！报告已保存至：{}", output_path);
    Ok(())
}