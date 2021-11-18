use crate::{sys, RdpError, Result};

#[derive(Debug)]
pub struct FreeRdp {
    inner: std::ptr::NonNull<sys::freerdp>,
}

impl FreeRdp {
    pub(crate) fn new(instance: *mut sys::freerdp) -> Self {
        Self {
            inner: std::ptr::NonNull::new(instance).unwrap(),
        }
    }

    pub fn connect(&self) -> Result<()> {
        let success = unsafe { sys::freerdp_connect(self.inner.as_ptr()) };
        if success == 1 {
            Ok(())
        } else {
            Err(RdpError::Failed("Failed to connect".into()))
        }
    }

    pub fn shall_disconnect(&self) -> bool {
        unsafe { sys::freerdp_shall_disconnect(self.inner.as_ptr()) == 1 }
    }
}
