use std::ffi::CStr;

use crate::sys;

/// Error enumerates all possible errors returned by this library.
#[derive(Debug)]
pub enum RdpError {
    /// A generic error.
    Failed(String),

    /// A FreeRDP error code.
    Code(u32),

    /// A FFI string error.
    NulError(std::ffi::NulError),

    /// Represents all other cases of `std::io::Error`.
    IOError(std::io::Error),
}

impl std::error::Error for RdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            RdpError::Failed(_) => None,
            RdpError::Code(_) => None,
            RdpError::NulError(ref err) => Some(err),
            RdpError::IOError(ref err) => Some(err),
        }
    }
}

impl std::fmt::Display for RdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            RdpError::Failed(ref err) => {
                write!(f, "{}", err)
            }
            RdpError::Code(code) => {
                write!(
                    f,
                    "{} ({:#x}): {}",
                    unsafe {
                        CStr::from_ptr(sys::freerdp_get_last_error_name(code))
                            .to_str()
                            .unwrap()
                    },
                    code,
                    unsafe {
                        CStr::from_ptr(sys::freerdp_get_last_error_string(code))
                            .to_str()
                            .unwrap()
                    },
                )
            }
            RdpError::NulError(ref err) => err.fmt(f),
            RdpError::IOError(ref err) => err.fmt(f),
        }
    }
}

impl From<std::io::Error> for RdpError {
    fn from(err: std::io::Error) -> RdpError {
        RdpError::IOError(err)
    }
}

impl From<std::ffi::NulError> for RdpError {
    fn from(err: std::ffi::NulError) -> RdpError {
        RdpError::NulError(err)
    }
}

pub type Result<T> = std::result::Result<T, RdpError>;
