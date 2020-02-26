use rand::SeedableRng as _;
use rand_chacha::ChaChaRng;
use std::time;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<ChaChaRng> = RefCell::new(ChaChaRng::from_entropy());
}

pub fn new_message_id() -> String {
    use rand::RngCore as _;

    let mut bytes = [0; 16];
    RNG.with(|rng| {
        rng.borrow_mut().fill_bytes(&mut bytes);
    });

    let id = uuid::Builder::from_bytes(bytes)
        .set_variant(uuid::Variant::RFC4122)
        .set_version(uuid::Version::Random)
        .build();

    let mut res = vec![0; uuid::adapter::Simple::LENGTH];
    id.to_simple().encode_upper(&mut res);
    String::from_utf8(res).unwrap()
}

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
