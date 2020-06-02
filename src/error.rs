//! Defines error type and variants that can be encountered with PolyPasswordHasher's runtime.

use std::error::Error;
use std::fmt;

// type alias for custom Result
pub type PPHResult<R> = Result<R, PPHError>;

/// defines the variants that exceptions can come as
#[derive(Debug)]
pub enum PPHErrorKind {
    ShardError,
    AuthError,
    FileError,
    SerError
}

/// the main error struct that encapsulates an error kind and a message
#[derive(Debug)]
pub struct PPHError {
    pub kind: PPHErrorKind,
    pub msg: String
}

impl fmt::Display for PPHError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PPHError with error kind {:?}: {}", self.kind, self.msg)
    }
}

impl From<std::io::Error> for PPHError {
    fn from(error: std::io::Error) -> Self {
        PPHError {
            kind: PPHErrorKind::FileError,
            msg: error.to_string()
        }
    }
}

impl From<serde_json::Error> for PPHError {
    fn from(error: serde_json::Error) -> Self {
        PPHError {
            kind: PPHErrorKind::SerError,
            msg: error.to_string()
        }
    }
}

impl Error for PPHError {}
