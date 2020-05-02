use crate::channel::MemberModes;
use crate::config::db;
use std::time;

const INIT_SQL: &str = include_str!("init.sql");

fn u32_to_member(val: u32) -> MemberModes {
    // TODO
    todo!()
}

pub struct Database {
    pool: sqlx::Pool<sqlx::SqliteConnection>,
}

impl Database {
    pub async fn new(info: db::Info) -> sqlx::Result<Self> {
        let mut builder = sqlx::Pool::builder()
            .max_size(info.max_size)
            .min_size(info.min_size)
            .connect_timeout(time::Duration::from_millis(info.connect_timeout));

        if let Some(idle_timeout) = info.idle_timeout {
            builder = builder.idle_timeout(time::Duration::from_millis(idle_timeout));
        }

        let pool = builder.build(&info.url).await?;
        sqlx::query(INIT_SQL).execute(&pool).await?;

        Ok(Self { pool })
    }

    pub async fn sasl_plain(&self, username: &str, password: &str) -> bool {
        // TODO
        todo!()
    }

    pub async fn sasl_external(&self, certhash: &[u8]) -> Option<String> {
        // TODO
        todo!()
    }
}
