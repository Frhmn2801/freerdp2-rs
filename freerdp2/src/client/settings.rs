use std::{
    ffi::{CStr, CString},
    ptr,
};

use crate::{sys, Result};

pub struct Settings {
    inner: ptr::NonNull<sys::rdpSettings>,
}

impl Settings {
    pub(crate) fn new(settings: *mut sys::rdpSettings) -> Self {
        Self {
            inner: std::ptr::NonNull::new(settings).unwrap(),
        }
    }

    pub fn set_server_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        unsafe {
            let hostname = match hostname {
                Some(hostname) => CString::new(hostname)?.into_raw(),
                None => std::ptr::null_mut(),
            };
            libc::free(self.inner.as_mut().ServerHostname.cast());
            self.inner.as_mut().ServerHostname = hostname;
        }
        Ok(())
    }

    pub fn server_hostname(&self) -> Option<String> {
        unsafe {
            let ptr = self.inner.as_ref().ServerHostname;
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
            }
        }
    }

    pub fn set_server_port(&mut self, port: u32) {
        unsafe {
            self.inner.as_mut().ServerPort = port;
        }
    }

    pub fn server_port(&self) -> u32 {
        unsafe { self.inner.as_ref().ServerPort }
    }

    pub fn set_username(&mut self, username: Option<&str>) -> Result<()> {
        unsafe {
            let username = match username {
                Some(username) => CString::new(username)?.into_raw(),
                None => std::ptr::null_mut(),
            };
            libc::free(self.inner.as_mut().Username.cast());
            self.inner.as_mut().Username = username;
        }
        Ok(())
    }

    pub fn username(&self) -> Option<String> {
        unsafe {
            let ptr = self.inner.as_ref().Username;
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
            }
        }
    }

    pub fn set_password(&mut self, password: Option<&str>) -> Result<()> {
        unsafe {
            let password = match password {
                Some(password) => CString::new(password)?.into_raw(),
                None => std::ptr::null_mut(),
            };
            libc::free(self.inner.as_mut().Password.cast());
            self.inner.as_mut().Password = password;
        }
        Ok(())
    }

    pub fn password(&self) -> Option<String> {
        unsafe {
            let ptr = self.inner.as_ref().Password;
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
            }
        }
    }

    pub fn set_allow_font_smoothing(&mut self, allow: bool) {
        unsafe {
            self.inner.as_mut().AllowFontSmoothing = allow as _;
        }
    }

    pub fn allow_font_smoothing(&self) -> bool {
        unsafe { self.inner.as_ref().AllowFontSmoothing != 0 }
    }

    pub fn set_allow_unanounced_orders_from_server(&mut self, allow: bool) {
        unsafe {
            self.inner.as_mut().AllowUnanouncedOrdersFromServer = allow as _;
        }
    }

    pub fn allow_unanounced_orders_from_server(&self) -> bool {
        unsafe { self.inner.as_ref().AllowUnanouncedOrdersFromServer != 0 }
    }
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("server_hostname", &self.server_hostname())
            .field("server_port", &self.server_port())
            .field("username", &self.username())
            .field("password", &self.password())
            .finish()
    }
}
