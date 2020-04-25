//! Authentication primitives and providers.
//!
//! ellidri supports multiple ways to use SASL, for example with a SQL database.  Each way is
//! implemented through a provider, a type that implements the `Provider` trait.  Each provider may
//! support multiple authentication mechanisms.

use crate::config::{db, SaslBackend};
use std::str;

/// Provider errors, used by the `Provider` trait.
#[derive(Debug)]
pub enum Error {
    /// Challenge response is not valid base64.
    BadBase64,

    /// Challenge response does not follow the mechanism's format.
    BadFormat,

    /// Challenge response is well-formed, but incorrect.
    InvalidCredentials,

    /// The provider cannot perform the authentication.
    ProviderUnavailable,

    /// Chosen mechanism is unsupported by the provider.
    UnsupportedMechanism,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl From<r2d2::Error> for Error {
    fn from(_: r2d2::Error) -> Self {
        Self::ProviderUnavailable
    }
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::ProviderUnavailable
    }
}

#[cfg(feature = "postgres")]
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::ProviderUnavailable
    }
}

/// Trait implemented by SASL authentication providers.
pub trait Provider: Send + Sync {
    /// Whether the SASL backend is available.
    ///
    /// If not, `start_auth` and `next_challenge` will return `Err(Error::ProviderUnavailable)`.
    fn is_available(&self) -> bool;

    /// Write the SASL mechanisms this provider supports, separated by commas (`,`).
    ///
    /// Example: `PLAIN,EXTERNAL`
    ///
    /// Used for capability advertisement.
    fn write_mechanisms(&self, buf: &mut String);

    /// Start the authentication process of a client.
    ///
    /// On success, returns an identifier that must be passed to `next_challenge` to continue the
    /// authentication, so that multiple clients can authenticate at the same time.
    fn start_auth(&self, mechanism: &str, next: &mut Vec<u8>) -> Result<usize, Error>;

    /// Given the authentication process identifier `auth`, and the response to the previous
    /// challenge from the client `response`, returns whether the client is authenticated or not.
    ///
    /// If the client is not authenticated yet, the next challenge to be sent to the client is
    /// appended to `next`.
    fn next_challenge(&self, auth: usize, response: &[u8], next: &mut Vec<u8>)
        -> Result<Option<String>, Error>;
}

/// A provider that doesn't do anything.
pub struct DummyProvider;

impl Provider for DummyProvider {
    fn is_available(&self) -> bool { false }
    fn write_mechanisms(&self, _: &mut String) {}
    fn start_auth(&self, _: &str, _: &mut Vec<u8>) -> Result<usize, Error> {
        Err(Error::ProviderUnavailable)
    }
    fn next_challenge(&self, _: usize, _: &[u8], _: &mut Vec<u8>) -> Result<Option<String>, Error> {
        Err(Error::ProviderUnavailable)
    }
}

pub trait Plain {
    fn plain(&self, user: &str, pass: &str) -> Result<(), Error>;
}

#[cfg(feature = "sqlite")]
impl Plain for r2d2::Pool<r2d2_sqlite::SqliteConnectionManager> {
    fn plain(&self, user: &str, pass: &str) -> Result<(), Error> {
        let conn = self.get()?;
        let mut stmt =
            conn.prepare("SELECT username FROM users WHERE username = ? AND password = ?")?;
        let mut rows = stmt.query(&[user, pass])?;
        rows.next()?.ok_or(Error::ProviderUnavailable)?;
        Ok(())
    }
}

#[cfg(feature = "postgres")]
impl<T> Plain for r2d2::Pool<r2d2_postgres::PostgresConnectionManager<T>>
    where T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket> + Clone + Sync + Send + 'static,
          T::TlsConnect: Send,
          T::Stream: Send,
          <T::TlsConnect as tokio_postgres::tls::TlsConnect<tokio_postgres::Socket>>::Future: Send,
{
    fn plain(&self, user: &str, pass: &str) -> Result<(), Error> {
        let mut conn = self.get()?;
        conn.query_one("SELECT username FROM users WHERE username = ? AND password = ?",
                       &[&user, &pass])?;
        Ok(())
    }
}

/// A provider that matches SASL challenges against data in a SQL database.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub struct DbProvider<M: r2d2::ManageConnection> {
    pool: r2d2::Pool<M>,
}

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl<M> DbProvider<M>
    where M: r2d2::ManageConnection
{
    fn try_from(val: M) -> Result<Self, r2d2::Error> {
        let pool = r2d2::Pool::new(val)?;
        Ok(DbProvider { pool })
    }
}

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl<M> Provider for DbProvider<M>
    where M: r2d2::ManageConnection,
          r2d2::Pool<M>: Plain,
{
    fn is_available(&self) -> bool {
        self.pool.get().is_ok()
    }

    fn write_mechanisms(&self, buf: &mut String) {
        buf.push_str("PLAIN");
    }

    fn start_auth(&self, mechanism: &str, _: &mut Vec<u8>) -> Result<usize, Error> {
        if mechanism != "PLAIN" {
            return Err(Error::UnsupportedMechanism);
        }
        Ok(0)
    }

    fn next_challenge(&self, _: usize, response: &[u8], _: &mut Vec<u8>)
        -> Result<Option<String>, Error>
    {
        let mut split = response.split(|b| *b == 0);
        let _ = split.next().ok_or(Error::BadFormat)?;
        let user = split.next().ok_or(Error::BadFormat)?;
        let pass = split.next().ok_or(Error::BadFormat)?;

        let user = str::from_utf8(user).map_err(|_| Error::BadFormat)?;
        let pass = str::from_utf8(pass).map_err(|_| Error::BadFormat)?;

        self.pool.plain(user, pass)?;
        Ok(Some(user.to_owned()))
    }
}

fn choose_db_provider(db_cfg: db::Info) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match db_cfg.driver {
        #[cfg(feature = "sqlite")]
        db::Driver::Sqlite => {
            log::info!("Loading SQLite database at {:?}", db_cfg.url);

            let manager = r2d2_sqlite::SqliteConnectionManager::file(db_cfg.url);
            let provider = DbProvider::try_from(manager)?;

            let conn = provider.pool.get()?;
            conn.query_row("SELECT name FROM SQLITE_MASTER WHERE name = 'users'",
                           rusqlite::NO_PARAMS,
                           |_row| Ok(()))
                .map_err(|_| "table \"users\" is missing")?;

            Ok(Box::new(provider))
        }
        #[cfg(feature = "postgres")]
        db::Driver::Postgres => {
            let no_tls = r2d2_postgres::postgres::NoTls;
            let config = db_cfg.url.parse()?;

            log::info!("Loading PostgreSQL database at {:?}", config);

            let manager = r2d2_postgres::PostgresConnectionManager::new(config, no_tls);
            let provider = DbProvider::try_from(manager)?;

            Ok(Box::new(provider))
        }
    }
}

/// Returns the first available provider given the `backend` type and the database URL `db_cfg`.
pub fn choose_provider(backend: SaslBackend, db_cfg: Option<db::Info>)
    -> Result<Box<dyn Provider>, Box<dyn std::error::Error>>
{
    match backend {
        SaslBackend::None => Ok(Box::new(DummyProvider)),
        SaslBackend::Database => choose_db_provider(db_cfg.unwrap()),
    }
}
