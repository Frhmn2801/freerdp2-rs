mod context;
pub use context::*;

mod settings;
pub use settings::*;

mod freerdp;
pub use freerdp::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RdpError, Result};

    #[test]
    fn it_works() {
        #[derive(Debug)]
        struct MyHandler {}

        impl Handler for MyHandler {
            fn global_init() -> Result<()> {
                dbg!();
                Ok(())
            }

            fn global_uninit() {
                dbg!();
            }

            fn client_new(_instance: &FreeRdp) -> Result<()> {
                dbg!();
                Ok(())
            }

            fn client_free(_instance: &FreeRdp) {
                dbg!();
            }

            fn client_start(&mut self) -> std::result::Result<(), i32> {
                Ok(())
            }

            fn client_stop(&mut self) -> std::result::Result<(), i32> {
                Ok(())
            }
        }

        let mut ctxt = Context::new(MyHandler {});
        dbg!(&ctxt);
        ctxt.client_start().unwrap();
        ctxt.client_stop().unwrap();
    }
}
