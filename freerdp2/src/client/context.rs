use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
    ptr::{self, NonNull},
};

use crate::{
    client::{FreeRdp, Settings},
    sys, RdpError, Result,
};

struct RdpContext {
    context: sys::rdpContext,
    handler: Option<Box<dyn Handler>>,
}

#[derive(Debug)]
pub struct Context {
    owned: bool,
    inner: ptr::NonNull<RdpContext>,

    pub settings: Settings,
    pub instance: FreeRdp,
}

#[derive(Debug)]
pub struct PubSub {
    inner: ptr::NonNull<sys::wPubSub>,
}

pub trait PubSubEvent {
    const NAME: &'static str;
}

#[derive(Debug)]
pub struct EventChannelConnected {}

impl PubSubEvent for EventChannelConnected {
    const NAME: &'static str = "ChannelConnected";
}

impl PubSub {
    pub(crate) fn new(pubsub: *mut sys::wPubSub) -> Self {
        Self {
            inner: std::ptr::NonNull::new(pubsub).unwrap(),
        }
    }

    pub fn subscribe<E, F>(&mut self, mut cb: F)
    where
        E: PubSubEvent,
        F: FnMut(E),
    {
        cb(todo!());
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if self.owned {
                sys::freerdp_client_context_free(self.inner.as_ptr().cast());
            }
        }
    }
}

pub enum VerifyCertificateResult {
    AcceptAndStore,
    AcceptOnlyThisSession,
    Fail,
}

impl From<VerifyCertificateResult> for u32 {
    fn from(res: VerifyCertificateResult) -> Self {
        match res {
            VerifyCertificateResult::AcceptAndStore => 1,
            VerifyCertificateResult::AcceptOnlyThisSession => 2,
            VerifyCertificateResult::Fail => 0,
        }
    }
}

pub trait Handler {
    fn global_init() -> Result<()>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn global_uninit()
    where
        Self: Sized,
    {
    }

    fn client_new(_instance: &FreeRdp) -> Result<()>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn client_free(_instance: &FreeRdp)
    where
        Self: Sized,
    {
    }

    fn client_start(&mut self) -> std::result::Result<(), i32> {
        Ok(())
    }

    fn client_stop(&mut self) -> std::result::Result<(), i32> {
        Ok(())
    }

    fn pre_connect(&mut self, context: &mut Context) -> Result<()> {
        let mut ps = context.pub_sub();
        ps.subscribe::<EventChannelConnected, _>(|e| dbg!());
        Ok(())
    }

    fn post_connect(&mut self) -> Result<()> {
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        _host: &str,
        _port: u16,
        _common_name: &str,
        _subject: &str,
        _issuer: &str,
        _fingerprint: &str,
        _flags: u32,
    ) -> VerifyCertificateResult {
        VerifyCertificateResult::AcceptOnlyThisSession
    }

    fn verify_certificate_changed(
        &mut self,
        _host: &str,
        _port: u16,
        _common_name: &str,
        _subject: &str,
        _issuer: &str,
        _new_fingerprint: &str,
        _old_subject: &str,
        _old_issuer: &str,
        _old_fingerprint: &str,
        _flags: u32,
    ) -> VerifyCertificateResult {
        VerifyCertificateResult::AcceptOnlyThisSession
    }

    fn present_gateway_message(
        &mut self,
        _type: u32,
        _is_display_mandatory: bool,
        _is_consent_mandatory: bool,
        msg: &str,
    ) -> Result<()> {
        eprintln!("{}", msg);
        Ok(())
    }

    fn logon_error_info(&mut self, _data: u32, _type: u32) -> i32 {
        1
    }
}

fn cvt_nz(error: c_int) -> Result<()> {
    if error == 0 {
        Ok(())
    } else {
        Err(RdpError::Code(error as _))
    }
}

impl Context {
    fn from_context(owned: bool, context: NonNull<RdpContext>) -> Self {
        let settings = Settings::new(unsafe { context.as_ref().context.settings });
        let instance = FreeRdp::new(unsafe { context.as_ref().context.instance });

        Self {
            owned,
            inner: context,
            settings,
            instance,
        }
    }

    pub fn new<H: 'static + Handler>(handler: H) -> Self {
        let mut entry_points = sys::rdp_client_entry_points_v1 {
            Size: std::mem::size_of::<sys::rdp_client_entry_points_v1>() as _,
            Version: sys::RDP_CLIENT_INTERFACE_VERSION,
            settings: std::ptr::null_mut(),
            GlobalInit: Some(rdp_global_init::<H>),
            GlobalUninit: Some(rdp_global_uninit::<H>),
            ClientNew: Some(rdp_client_new::<H>),
            ClientFree: Some(rdp_client_free::<H>),
            ClientStart: Some(rdp_client_start::<H>),
            ClientStop: Some(rdp_client_stop::<H>),
            ContextSize: std::mem::size_of::<RdpContext>() as _,
        };

        let context = unsafe { sys::freerdp_client_context_new(&mut entry_points) };
        let mut context = std::ptr::NonNull::new(context as *mut RdpContext).unwrap();
        unsafe { context.as_mut().handler = Some(Box::new(handler)) };

        Self::from_context(true, context)
    }

    pub fn client_start(&mut self) -> Result<()> {
        cvt_nz(unsafe { sys::freerdp_client_start(self.inner.as_ptr().cast()) })
    }

    pub fn client_stop(&mut self) -> Result<()> {
        cvt_nz(unsafe { sys::freerdp_client_stop(self.inner.as_ptr().cast()) })
    }

    pub fn check_event_handles(&self) -> bool {
        unsafe { sys::freerdp_check_event_handles(self.inner.as_ptr().cast()) == 1 }
    }

    pub fn last_error(&self) -> Result<()> {
        cvt_nz(unsafe { sys::freerdp_get_last_error(self.inner.as_ptr().cast()) as _ })
    }

    fn pub_sub(&mut self) -> PubSub {
        PubSub::new(unsafe { self.inner.as_mut() }.context.pubSub)
    }
}

extern "C" fn rdp_global_init<H: Handler>() -> sys::BOOL {
    H::global_init().is_ok() as _
}

extern "C" fn rdp_global_uninit<H: Handler>() {
    H::global_uninit()
}

extern "C" fn rdp_instance_pre_connect<H: Handler>(instance: *mut sys::freerdp) -> sys::BOOL {
    let mut ctxt =
        unsafe { std::ptr::NonNull::new((*instance).context as *mut RdpContext).unwrap() };
    let handler = unsafe { ctxt.as_mut() }.handler.as_mut().unwrap();

    handler
        .pre_connect(&mut Context::from_context(false, ctxt))
        .is_ok() as _
}

extern "C" fn rdp_instance_post_connect<H: Handler>(instance: *mut sys::freerdp) -> sys::BOOL {
    let ctxt = unsafe {
        std::ptr::NonNull::new((*instance).context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    handler.post_connect().is_ok() as _
}

extern "C" fn rdp_instance_post_disconnect<H: Handler>(_instance: *mut sys::freerdp) {
    todo!()
}

extern "C" fn rdp_instance_authenticate<H: Handler>(
    _instance: *mut sys::freerdp,
    _username: *mut *mut c_char,
    _password: *mut *mut c_char,
    _domain: *mut *mut c_char,
) -> sys::BOOL {
    todo!()
}

extern "C" fn rdp_instance_verify_certificate<H: Handler>(
    instance: *mut sys::freerdp,
    host: *const ::std::os::raw::c_char,
    port: sys::UINT16,
    common_name: *const ::std::os::raw::c_char,
    subject: *const ::std::os::raw::c_char,
    issuer: *const ::std::os::raw::c_char,
    fingerprint: *const ::std::os::raw::c_char,
    flags: sys::DWORD,
) -> sys::DWORD {
    let ctxt = unsafe {
        std::ptr::NonNull::new((*instance).context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    handler
        .verify_certificate(
            unsafe { CStr::from_ptr(host).to_str().unwrap() },
            port,
            unsafe { CStr::from_ptr(common_name).to_str().unwrap() },
            unsafe { CStr::from_ptr(subject).to_str().unwrap() },
            unsafe { CStr::from_ptr(issuer).to_str().unwrap() },
            unsafe { CStr::from_ptr(fingerprint).to_str().unwrap() },
            flags,
        )
        .into()
}

extern "C" fn rdp_instance_verify_changed_certificate<H: Handler>(
    instance: *mut sys::freerdp,
    host: *const ::std::os::raw::c_char,
    port: sys::UINT16,
    common_name: *const ::std::os::raw::c_char,
    subject: *const ::std::os::raw::c_char,
    issuer: *const ::std::os::raw::c_char,
    new_fingerprint: *const ::std::os::raw::c_char,
    old_subject: *const ::std::os::raw::c_char,
    old_issuer: *const ::std::os::raw::c_char,
    old_fingerprint: *const ::std::os::raw::c_char,
    flags: sys::DWORD,
) -> sys::DWORD {
    let ctxt = unsafe {
        std::ptr::NonNull::new((*instance).context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    handler
        .verify_certificate_changed(
            unsafe { CStr::from_ptr(host).to_str().unwrap() },
            port,
            unsafe { CStr::from_ptr(common_name).to_str().unwrap() },
            unsafe { CStr::from_ptr(subject).to_str().unwrap() },
            unsafe { CStr::from_ptr(issuer).to_str().unwrap() },
            unsafe { CStr::from_ptr(new_fingerprint).to_str().unwrap() },
            unsafe { CStr::from_ptr(old_subject).to_str().unwrap() },
            unsafe { CStr::from_ptr(old_issuer).to_str().unwrap() },
            unsafe { CStr::from_ptr(old_fingerprint).to_str().unwrap() },
            flags,
        )
        .into()
}

extern "C" fn rdp_instance_present_gateway_message<H: Handler>(
    instance: *mut sys::freerdp,
    type_: sys::UINT32,
    is_display_mandatory: sys::BOOL,
    is_consent_mandatory: sys::BOOL,
    length: sys::size_t,
    message: *const sys::WCHAR,
) -> sys::BOOL {
    let ctxt = unsafe {
        std::ptr::NonNull::new((*instance).context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    let msg = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(message, length as _) });
    handler
        .present_gateway_message(
            type_,
            is_display_mandatory != 0,
            is_consent_mandatory != 0,
            &msg,
        )
        .is_ok() as _
}

extern "C" fn rdp_instance_logon_error_info<H: Handler>(
    instance: *mut sys::freerdp,
    data: sys::UINT32,
    type_: sys::UINT32,
) -> i32 {
    let ctxt = unsafe {
        std::ptr::NonNull::new((*instance).context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    handler.logon_error_info(data, type_)
}

extern "C" fn rdp_client_new<H: Handler>(
    instance: *mut sys::freerdp,
    _context: *mut sys::rdpContext,
) -> sys::BOOL {
    unsafe {
        let mut instance = std::ptr::NonNull::new(instance).unwrap().as_mut();
        instance.PreConnect = Some(rdp_instance_pre_connect::<H>);
        instance.PostConnect = Some(rdp_instance_post_connect::<H>);
        instance.PostDisconnect = Some(rdp_instance_post_disconnect::<H>);
        instance.Authenticate = Some(rdp_instance_authenticate::<H>);
        instance.VerifyCertificateEx = Some(rdp_instance_verify_certificate::<H>);
        instance.VerifyChangedCertificateEx = Some(rdp_instance_verify_changed_certificate::<H>);
        instance.PresentGatewayMessage = Some(rdp_instance_present_gateway_message::<H>);
        instance.LogonErrorInfo = Some(rdp_instance_logon_error_info::<H>);
    }

    // can't call self.client_new() since it isn't yet returned from context_new...
    H::client_new(&FreeRdp::new(instance)).is_ok() as _
}

extern "C" fn rdp_client_free<H: Handler>(
    instance: *mut sys::freerdp,
    _context: *mut sys::rdpContext,
) {
    // can't call self.client_free() since it may not yet be returned from context_new...
    H::client_free(&FreeRdp::new(instance))
}

extern "C" fn rdp_client_start<H: Handler>(context: *mut sys::rdpContext) -> c_int {
    let ctxt = unsafe {
        std::ptr::NonNull::new(context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    match handler.client_start() {
        Ok(_) => 0,
        Err(e) => e,
    }
}

extern "C" fn rdp_client_stop<H: Handler>(context: *mut sys::rdpContext) -> c_int {
    let ctxt = unsafe {
        std::ptr::NonNull::new(context as *mut RdpContext)
            .unwrap()
            .as_mut()
    };
    let handler = ctxt.handler.as_mut().unwrap();

    match handler.client_stop() {
        Ok(_) => 0,
        Err(e) => e,
    }
}
