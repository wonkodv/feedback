use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::rc::Rc;

use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::state::{self, Session, State, };
use url::form_urlencoded;

use thiserror;

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("User Error {0}")]
    UserError(String),

    #[error("Bad Request {0}")]
    ApiMisuse(String),

    #[error("Error {0}")]
    ProgramError(String),

    #[error("HyperError {0}")]
    HyperError(#[from] hyper::Error),
}
use ServerError::*;

async fn handle_request(
    state: Rc<RefCell<State>>,
    req: Request<Body>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    let mut req = req;
    response
        .headers_mut()
        .insert("Content-Type", HeaderValue::from_static("text/html"));

    let post_params: HashMap<String, String>;
    if req.method() == Method::POST {
        let post_body = hyper::body::to_bytes(req.body_mut()).await?;
        post_params = form_urlencoded::parse(post_body.as_ref())
            .into_owned()
            .collect();
    } else {
        post_params = HashMap::new();
    }

    let get_params: HashMap<String, String>;
    if let Some(query) = req.uri().query() {
        get_params = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    } else {
        get_params = HashMap::new();
    }

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
            {
                let mut state = state.borrow_mut();
                let session = state.new_session(
                    &post_params
                        .get("title")
                        .ok_or_else(|| ApiMisuse("title missing".to_string()))?,
                );

                *response.body_mut() = Body::from(format!(
                    r#"
                    <form method=POST action="/update" target=iframe>
                        <input type="hidden" name="private" value="{}">
                    </form>
                    <iframe name=iframe>
                    </iframe>
                    <script>
                        function update() {{document.querySelector("form").submit();}}
                        setInterval(update, 1000);
                    </script>

                    New Session named {} 
                    Vote <a href="/vote?public={}">here</a>
                "#,
                    session.private_id(),
                    session.title(),
                    session.public_id()
                ));
            }
            Ok(())
        }
        (&Method::POST, "/update") => {
            {
                let mut state = state.borrow_mut();
                let session = state
                    .session_by_private_key(
                        post_params
                            .get("private")
                            .ok_or_else(|| ApiMisuse("private id missing".to_string()))?
                            .parse()
                            .map_err(|e| ApiMisuse(format!("private id not a number {}", e)))?,
                    )
                    .ok_or_else(|| ApiMisuse("Bad Id".to_string()))?;
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
        (&Method::GET, "/vote") => {
            let user =  state::new_user_id();
            *response.body_mut() = Body::from(format!(
                r#"
                    <form method=POST action="/vote" target=iframe>
                        <input type="hidden" name="public" value="{}">
                        <input type="hidden" name="user" value="{}">
                        <input type=submit name=vote value="&#x1f44e;" >
                        <input type=submit name=vote value="&#x1f44d;" >
                    </form>
                    <iframe name=iframe>
                    </iframe>
                "#,
                get_params
                    .get("public")
                    .ok_or_else(|| ApiMisuse("id missing".to_string()))?,
                user,
            ));
            Ok(())
        }
        (&Method::POST, "/vote") => {
            let mut state = state.borrow_mut();

            let vote = post_params
                .get("vote")
                .ok_or_else(|| ApiMisuse("vote missing".to_string()))?;
            let user_id = post_params
                .get("user")
                .ok_or_else(|| ApiMisuse("user missing".to_string()))?
                .parse()
                .map_err(|e| ApiMisuse(format!("user id wrong {}", e)))?
                ;
            let public_id = post_params
                .get("public")
                .ok_or_else(|| ApiMisuse("id missing".to_string()))?
                .parse()
                .map_err(|e| ApiMisuse(format!("Session Id wrong {}", e)))?
                ;

            let session = state.session_by_public_key(public_id)
                .ok_or_else(|| ApiMisuse("no such session".to_string()))?
                ;

            session.vote(user_id, vote.to_owned());


            *response.body_mut() = Body::from(format!(
                r#"
                    You changed your vote to {}
                "#,
                vote,
            ));
            Ok(())
        }
        r => Err(ApiMisuse(format!("no path {:?}", r))),
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
