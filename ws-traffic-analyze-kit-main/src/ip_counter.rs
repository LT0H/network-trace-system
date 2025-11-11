use std::collections::{HashMap, HashSet};
use std::error::Error;
use csv::Reader;
use std::fs::File;
use std::io::{BufWriter, Write};

pub(crate) fn ip_counter() -> Result<(), Box<dyn Error>> {
    let mut csv_reader = Reader::from_path("xk.csv")?;
    let mut ip_user_map: HashMap<String, HashSet<String>> = HashMap::new();

    let whitelist_ip = vec!["219.217.200.201".to_string()];

    for record in csv_reader.records() {
        let record = record?;
        let ip = record.get(1).unwrap().to_string();
        let user = record.get(2).unwrap().to_string();
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

    let mut file = BufWriter::new(File::create("ip_counts.txt")?);
    file.write_all(&output_buffer)?;

    Ok(())
}
