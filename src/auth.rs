//! Authentication primitives and providers.
//!
//! ellidri supports multiple ways to use SASL, for example with a SQL database.  Each way is
//! implemented through a provider, a type that implements the `Provider` trait.  Each provider may
//! support multiple authentication mechanisms.

use crate::client::AUTHENTICATE_CHUNK_LEN;
use crate::config::{db, SaslBackend};
use crate::message::{Command, ReplyBuffer};
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

    /// Choosen mechanism is unsupported by the provider.
    UnsupportedMechanism,
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
    /// Used for capability advertisment.
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

// TODO better name
pub trait Plain {
    fn plain(&self, user: &str, pass: &str) -> Result<(), Error>;
}

#[cfg(feature = "sqlite")]
impl Plain for r2d2::Pool<r2d2_sqlite::SqliteConnectionManager> {
    fn plain(&self, user: &str, pass: &str) -> Result<(), Error> {
        let conn = self.get().map_err(|_| Error::ProviderUnavailable)?;
        let mut stmt = conn.prepare("SELECT username FROM users WHERE username = ? AND password = ?")
            .map_err(|_| Error::ProviderUnavailable)?;
        let mut rows = stmt.query(&[user, pass])
            .map_err(|_| Error::ProviderUnavailable)?;
        rows.next()
            .map_err(|_| Error::ProviderUnavailable)?
            .ok_or(Error::ProviderUnavailable)?;

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
        let mut conn = self.get().map_err(|_| Error::ProviderUnavailable)?;
        conn.query_one("SELECT username FROM users WHERE username = ? AND password = ?",
                       &[&user, &pass])
            .map_err(|_| Error::ProviderUnavailable)?;
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

fn choose_db_provider(url: db::Url) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match url.0 {
        #[cfg(feature = "sqlite")]
        db::Driver::Sqlite => {
            log::info!("Loading SQLite database at {:?}", url.1);

            let manager = r2d2_sqlite::SqliteConnectionManager::file(&url.1);
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
            let config = url.1.parse()?;

            log::info!("Loading PostgreSQL database at {:?}", config);

            let manager = r2d2_postgres::PostgresConnectionManager::new(config, no_tls);
            let provider = DbProvider::try_from(manager)?;

            Ok(Box::new(provider))
        }
    }
}

/// Returns the first available provider given the `backend` type and the database URL `db_url`.
pub fn choose_provider(backend: SaslBackend, db_url: Option<db::Url>)
    -> Result<Box<dyn Provider>, Box<dyn std::error::Error>>
{
    match backend {
        SaslBackend::None => Ok(Box::new(DummyProvider)),
        SaslBackend::Database => choose_db_provider(db_url.unwrap()),
    }
}

/// Encode `buf` in the base64 format, and split it in 400-byte chunks to append to AUTHENTICATE
/// messages.
pub fn write_buffer<T>(rb: &mut ReplyBuffer, buf: T)
    where T: AsRef<[u8]>
{
    if buf.as_ref().is_empty() {
        rb.message("", Command::Authenticate).param("+");
        return;
    }

    let encoded = base64::encode(buf);
    let mut i = 0;
    while i < encoded.len() {
        let max = encoded.len().min(i + AUTHENTICATE_CHUNK_LEN);
        let chunk = &encoded[i..max];
        rb.message("", Command::Authenticate).param(chunk);
        i = max;
    }
    if i % AUTHENTICATE_CHUNK_LEN == 0 {
        rb.message("", Command::Authenticate).param("+");
    }
}
