use freerdp2::client::*;

#[derive(Debug)]
struct MyHandler {}

impl Handler for MyHandler {
    fn client_start(&mut self) -> Result<(), i32> {
        Ok(())
    }

    fn client_stop(&mut self) -> Result<(), i32> {
        Ok(())
    }
}

fn main() {
    let mut ctxt = Context::new(MyHandler {});

    ctxt.client_start().unwrap();
    ctxt.settings
        .set_server_hostname(Some("localhost"))
        .unwrap();
    ctxt.settings.set_server_port(3389);
    ctxt.settings.set_username(Some("user")).unwrap();
    ctxt.settings.set_password(Some("pass")).unwrap();

    ctxt.instance.connect().unwrap();

    while !ctxt.instance.shall_disconnect() {
        if !ctxt.check_event_handles() {
            if let Err(e) = ctxt.last_error() {
                eprintln!("{}", e);
                break;
            }
        }
    }

    ctxt.client_stop().unwrap();
}
