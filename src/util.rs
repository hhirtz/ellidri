use std::time;

pub fn time_str() -> String {
    chrono::Local::now().to_rfc2822()
}

pub fn time() -> u64 {
    time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .map_or_else(|_| { log::error!("Computer clock set before 01/01/1970?"); 0 }, |d| d.as_secs())
}
