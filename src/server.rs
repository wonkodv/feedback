use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::rc::Rc;

use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::state::{Session, State};
use url::form_urlencoded;

async fn handle_request(
    state: Rc<RefCell<State>>,
    req: Request<Body>,
    response: &mut Response<Body>,
) -> Result<(), Box<dyn Error>> {
    response.headers_mut().insert("Content-Type", HeaderValue::from_static("text/html"));
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from(
                r#"
                <form method="POST" action="/new" >
                <input type=text name=title>
                <button type=submit>New</button>
                </form>
                "#,
            );
            Ok(())
        }
        (&Method::POST, "/new") => {
            let params = hyper::body::to_bytes(req).await.unwrap();
            let params: HashMap<String, String> = form_urlencoded::parse(params.as_ref())
                .into_owned()
                .collect();

            {
                let mut state = state.borrow_mut();
                let session =
                    state.new_session(&params.get("title").unwrap_or(&"no title".to_owned()));

                *response.body_mut() = Body::from(format!(
                    r#"
                    <form method=POST action="/update" target=iframe>
                        <input type="hidden" name="private" value="{}">
                    </form>
                    <iframe name=iframe src=/update>
                    </iframe>
                    <script>
                        function update() {{document.querySelector("form").submit();}}
                        setInterval(update, 1000);
                    </script>

                    New Session named {} 
                    Vote <a href="/vote#{}">here</a>
                "#,
                    session.private_id(),
                    session.title(),
                    session.public_id()
                ));
            }
            Ok(())
        }
        (&Method::POST, "/update") => {
            let params = hyper::body::to_bytes(req).await.unwrap();
            let params: HashMap<String, String> = form_urlencoded::parse(params.as_ref())
                .into_owned()
                .collect();
            {
                let mut state = state.borrow_mut();
                let session = state
                    .get_session_by_private(params.get("private").unwrap().parse().unwrap())
                    .unwrap();
                let mut body = String::new();
                body.push_str("<ul>");
                for (v, c) in session.votes() {
                    body.push_str(&format!("<li>{} - {}</li>", c, v));
                }
                body.push_str("</ul>");
                *response.body_mut() = Body::from(body);
            }
            Ok(())
        }
        r => Err(format!("no route {:?}", r).into()),
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    eprintln!("Shutting down");
}

pub fn run() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, server_task());
}

async fn server_task() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let state = Rc::new(RefCell::new(State::default()));

    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move {
                    let mut response = Response::new(Body::empty());
                    if let Err(e) = handle_request(state.clone(), req, &mut response).await {
                        eprintln!("Error {}", e);
                        *response.status_mut() = StatusCode::NOT_FOUND;
                    }

                    Ok::<_, Infallible>(response)
                }
            }))
        }
    });

    let server = Server::bind(&addr).executor(LocalExec).serve(make_svc);
    let server = server.with_graceful_shutdown(shutdown_signal());
    println!("Listening on http://{}", addr);

    // The server would block on current thread to await !Send futures.
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

// Since the Server needs to spawn some background tasks, we needed
// to configure an Executor that can spawn !Send futures...
#[derive(Clone, Copy, Debug)]
struct LocalExec;

impl<F> hyper::rt::Executor<F> for LocalExec
where
    F: std::future::Future + 'static, // not requiring `Send`
{
    fn execute(&self, fut: F) {
        // This will spawn into the currently running `LocalSet`.
        tokio::task::spawn_local(fut);
    }
}
