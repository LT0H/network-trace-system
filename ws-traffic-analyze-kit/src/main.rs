mod ip_counter;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 改进错误处理，显示详细错误信息而非简单崩溃
    if let Err(e) = ip_counter::ip_counter() {
        eprintln!("分析失败: {}", e);
        std::process::exit(1);
    }
    Ok(())
}