#[cfg(feature = "tls")]
pub use tls_enabled::{Acceptor, IdentityStore};

#[cfg(not(feature = "tls"))]
pub use tls_disabled::{Acceptor, IdentityStore};

#[cfg(feature = "tls")]
mod tls_enabled {
    use std::collections::HashMap;
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::{fs, io};
    use tokio_rustls::TlsAcceptor;

    pub type Acceptor = Arc<TlsAcceptor>;

    /// [Acceptor] cache, to avoid reading the same files several times.
    #[derive(Default)]
    pub struct IdentityStore {
        acceptors: HashMap<PathBuf, Acceptor>,
    }

    impl IdentityStore {
        /// Retrieves the acceptor at `path`, or get it from the cache if it has already been built.
        pub fn acceptor<P1, P2>(
            &mut self,
            cert: P1,
            key: P2,
        ) -> Result<Acceptor, Box<dyn Error + 'static>>
        where
            P1: AsRef<Path> + Into<PathBuf>,
            P2: AsRef<Path> + Into<PathBuf>,
        {
            if let Some(acceptor) = self.acceptors.get(cert.as_ref()) {
                Ok(acceptor.clone())
            } else {
                let acceptor = Arc::new(build_acceptor(cert.as_ref(), key.as_ref())?);
                self.acceptors.insert(cert.into(), acceptor.clone());
                Ok(acceptor)
            }
        }
    }

    /// Read the file at `p`, parse the identity and builds an [Acceptor] object.
    fn build_acceptor(
        certfile: &Path,
        keyfile: &Path,
    ) -> Result<TlsAcceptor, Box<dyn Error + 'static>> {
        use tokio_rustls::rustls::internal::pemfile;
        use tokio_rustls::rustls::{NoClientAuth, ServerConfig};

        let mut config = ServerConfig::new(NoClientAuth::new());

        log::info!("Loading TLS certificate from {:?}", certfile.display());
        let cert = fs::read(certfile).map_err(|err| {
            log::error!("Failed to read {:?}: {}", certfile.display(), err);
            err
        })?;
        let cert = pemfile::certs(&mut cert.as_ref()).map_err(|_| {
            log::error!("Failed to parse {:?}", certfile.display());
            ""
        })?;

        log::info!("Loading TLS private key from {:?}", keyfile.display());
        let key = fs::read(keyfile).map_err(|err| {
            log::error!("Failed to read {:?}: {}", keyfile.display(), err);
            err
        })?;
        let key = {
            let mut keys = pemfile::pkcs8_private_keys(&mut key.as_ref()).map_err(|_| {
                log::error!("Failed to parse {:?}", keyfile.display());
                ""
            })?;
            if keys.is_empty() {
                log::error!("No key found in {:?}", keyfile.display());
                return Err(Box::new(io::Error::new(io::ErrorKind::Other, "")));
            }
            keys.remove(0)
        };

        config.set_single_cert(cert, key).map_err(|err| {
            log::error!(
                "Failed to associate {:?} with {:?}: {}",
                certfile.display(),
                keyfile.display(),
                err
            );
            err
        })?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

#[cfg(not(feature = "tls"))]
mod tls_disabled {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    pub type Acceptor = DummyAcceptor;

    #[derive(Clone)]
    pub struct DummyAcceptor;

    #[derive(Debug)]
    struct UnimplementedError;

    impl std::fmt::Display for UnimplementedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "tls support disabled")
        }
    }

    impl Error for UnimplementedError {}

    #[derive(Default)]
    pub struct IdentityStore;

    impl IdentityStore {
        pub fn acceptor<P1, P2>(
            &mut self,
            cert: P1,
            key: P2,
        ) -> Result<Acceptor, Box<dyn Error + 'static>>
        where
            P1: AsRef<Path> + Into<PathBuf>,
            P2: AsRef<Path> + Into<PathBuf>,
        {
            log::error!(
                "TLS support is disabled, cannot load cert {:?} and key {:?}",
                cert.as_ref().display(),
                key.as_ref().display(),
            );
            Err(Box::new(UnimplementedError))
        }
    }
}
