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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Plain,
    External,
}

#[derive(Clone, Copy, Debug)]
pub enum Payload<'a> {
    Abort,
    Mechanism(Mechanism),
    Chunk(&'a str),
}

impl<'a> From<&'a str> for Payload<'a> {
    fn from(val: &'a str) -> Self {
        match val {
            "*" => Self::Abort,
            "+" => Self::Chunk(""),
            "PLAIN" => Self::Mechanism(Mechanism::Plain),
            "EXTERNAL" => Self::Mechanism(Mechanism::External),
            val => Self::Chunk(val),
        }
    }
}
