use std::time;

pub fn time_precise() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn time_str() -> String {
    chrono::Local::now().to_rfc2822()
}

pub fn time() -> u64 {
    match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
        Ok(unix_time) => unix_time.as_secs(),
        Err(_) => {
            log::error!("Computer clock set before 01/01/1970?");
            0
        }
    }
}
