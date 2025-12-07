mod ip_counter;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    ip_counter::ip_counter().expect("IP Counter Failed");

    Ok(())
}
