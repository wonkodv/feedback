use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::rc::Rc;

use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::state::{self, Poll, State};
use url::form_urlencoded;

use thiserror;

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("User Error {0}")]
    UserError(String),

    #[error("Not Found {0}")]
    NotFound(String),

    #[error("Bad Request {0}")]
    ApiMisuse(String),

    #[error("Error {0}")]
    ProgramError(String),

    #[error("HyperError {0}")]
    HyperError(#[from] hyper::Error),
}
use ServerError::*;

fn handle_query(
    state: Rc<RefCell<State>>,
    req: &Request<Body>,
    response: &mut Response<Body>,
    get_params: &HashMap<String, String>,
    post_params: &HashMap<String, String>,
) -> Result<(), ServerError> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => dsp_new(response),
        (&Method::POST, "/new") => act_new(&state, post_params, response),
        (&Method::POST, "/show_results") => dsp_results(req, get_params, &state, response),
        (&Method::POST, "/update") => dsp_update_results(&state, post_params, response),
        (&Method::POST, "/clear") => act_clear(&state, post_params, response),
        (&Method::GET, "/vote") => dsp_vote(response, get_params),
        (&Method::POST, "/vote") => act_vote(state, post_params, response),
        r => Err(ApiMisuse(format!("no path {:?}", r))),
    }
}

/// Show Dialog to create new Poll
fn dsp_new(response: &mut Response<Body>) -> Result<(), ServerError> {
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

/// Create new Poll
fn act_new(
    state: &Rc<RefCell<State>>,
    post_params: &HashMap<String, String>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    {
        let mut state = state.borrow_mut();
        let poll = state.new_poll(
            &post_params
                .get("title")
                .ok_or_else(|| ApiMisuse("title missing".to_string()))?,
        );

        response.headers_mut().insert(
            "Location",
            HeaderValue::from_str(&format!("/show_results?key={}", poll.private_id()))
                .expect("valid header"),
        );
        *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    }
    Ok(())
}

/// show the Poll Results View
fn dsp_results(
    req: &Request<Body>,
    get_params: &HashMap<String, String>,
    state: &Rc<RefCell<State>>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    {
        let key: u64 = get_params
            .get("key")
            .ok_or_else(|| ApiMisuse("key missing".to_string()))?
            .parse()
            .map_err(|e| ApiMisuse(format!("private id not a number {}", e)))?;
        let mut state = state.borrow_mut();
        let poll = state
            .poll_by_private_key(key)
            .ok_or_else(|| ApiMisuse("no such poll".to_string()))?;
        let private_id = poll.private_id();
        let title = poll.title();
        let public_id = poll.public_id();

        let host = req
            .headers()
            .get("Host")
            .map(|hv| hv.to_str().ok().unwrap_or(""))
            .unwrap_or("");
        let u = format!("http://{host}/vote?id={public_id}");

        *response.body_mut() = Body::from(format!(
            r##"
                    <a href="/" target=_blank>New Poll</a>
                    <br>
                    <form id="refreshform" method=POST action="/update" target=iframe>
                        <input type="hidden" name="key" id=key value="{private_id}">
                    </form>
                    <iframe name=iframe>
                    </iframe>
                    <script>
                        window.history.pushState({{"key":{private_id}}}, "Title", "/show_results");
                        function update() {{document.querySelector("#refreshform").submit();}}
                        setInterval(update, 1000);
                    </script>
                    <br>
                    New Poll named {title}
                    <br>
                    <form method=POST action="/clear" target=iframe>
                        <input type="hidden" name="key" id=key value="{private_id}">
                        <button type=submit>Clear</button>
                    </form>
                    <br>
                    Vote at {url}
                    <img src="https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl={u}">
                "##,
        ));
    }
    Ok(())
}

/// Render the Poll Results for the iframe
fn dsp_update_results(
    state: &Rc<RefCell<State>>,
    post_params: &HashMap<String, String>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    {
        let mut state = state.borrow_mut();
        let poll = state
            .poll_by_private_key(
                post_params
                    .get("key")
                    .ok_or_else(|| ApiMisuse("key missing".to_string()))?
                    .parse()
                    .map_err(|e| ApiMisuse(format!("key not a number {}", e)))?,
            )
            .ok_or_else(|| ApiMisuse("Bad Id".to_string()))?;
        let mut body = String::new();
        body.push_str("<ul>");
        for (v, c) in poll.votes() {
            body.push_str(&format!("<li>{} - {}</li>", c, v));
        }
        body.push_str("</ul>");
        *response.body_mut() = Body::from(body);
    }
    Ok(())
}

/// Clear current Poll
fn act_clear(
    state: &Rc<RefCell<State>>,
    post_params: &HashMap<String, String>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    {
        let mut state = state.borrow_mut();
        let poll = state
            .poll_by_private_key(
                post_params
                    .get("key")
                    .ok_or_else(|| ApiMisuse("key missing".to_string()))?
                    .parse()
                    .map_err(|e| ApiMisuse(format!("key not a number {}", e)))?,
            )
            .ok_or_else(|| ApiMisuse("Bad Id".to_string()))?;

        poll.clear();

        response.headers_mut().insert(
            "Location",
            HeaderValue::from_str(&format!("/show_results")).expect("valid header"),
        );
        *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    }
    Ok(())
}

fn dsp_vote(
    response: &mut Response<Body>,
    get_params: &HashMap<String, String>,
) -> Result<(), ServerError> {
    let user = state::new_user_id(); // TODO: currently, every page reload is a new user, this
                                     // should be done with cookies
    let poll_id = get_params
        .get("id")
        .ok_or_else(|| ApiMisuse("id missing".to_string()))?;
    *response.body_mut() = Body::from(format!(
        r#" Hi, you are user {user}. Please vote:
                    <form method=POST action="/vote" target=iframe>
                        <input type="hidden" name="id" value="{poll_id}">
                        <input type="hidden" name="user" value="{user}">
                        <input type=submit name=vote value="👍" >
                        <input type=submit name=vote value="👎" >
                        <input type=submit name=vote value="🐇" >
                        <input type=submit name=vote value="🐢" >
                    </form>
                    <iframe name=iframe>
                    </iframe>
                "#,
    ));
    Ok(())
}

/// Send a vote
fn act_vote(
    state: Rc<RefCell<State>>,
    post_params: &HashMap<String, String>,
    response: &mut Response<Body>,
) -> Result<(), ServerError> {
    let mut state = state.borrow_mut();
    let vote = post_params
        .get("vote")
        .ok_or_else(|| ApiMisuse("vote missing".to_string()))?;
    let user_id = post_params
        .get("user")
        .ok_or_else(|| ApiMisuse("user missing".to_string()))?
        .parse()
        .map_err(|e| ApiMisuse(format!("user id wrong {}", e)))?;
    let public_id = post_params
        .get("id")
        .ok_or_else(|| ApiMisuse("id missing".to_string()))?
        .parse()
        .map_err(|e| ApiMisuse(format!("Poll Id wrong {}", e)))?;
    let poll = state
        .poll_by_public_key(public_id)
        .ok_or_else(|| ApiMisuse("no such poll".to_string()))?;
    poll.vote(user_id, vote.to_owned());
    *response.body_mut() = Body::from(format!(
        r#"
                    You changed your vote to {}
                "#,
        vote,
    ));
    Ok(())
}

async fn parse_params(
    req: &mut Request<Body>,
) -> Result<(HashMap<String, String>, HashMap<String, String>), ServerError> {
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

    Ok((get_params, post_params))
}

async fn handle_request(
    state: Rc<RefCell<State>>,
    req: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    let mut req = req;

    response.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/html; Charset=UTF-8"),
    );

    let get_params;
    let post_params;
    match parse_params(&mut req).await {
        Ok(params) => {
            get_params = params.0;
            post_params = params.1;
        }
        Err(e) => {
            eprintln!("HyperError {}", e);
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(response);
        }
    }

    let r = handle_query(state, &mut req, &mut response, &get_params, &post_params);

    match r {
        Ok(()) => {}
        Err(UserError(msg)) => {
            eprintln!("API Missuse {:?} {}", req, msg);
            *response.status_mut() = StatusCode::EXPECTATION_FAILED;
        }
        Err(NotFound(e)) => {
            *response.status_mut() = StatusCode::NOT_FOUND;
            *response.body_mut() = "Not Found".into();
        }
        Err(ApiMisuse(msg)) => {
            eprintln!("API Missuse {:?} {}", req, msg);
            *response.status_mut() = StatusCode::EXPECTATION_FAILED;
        }
        Err(HyperError(e)) => {
            eprintln!("HyperError {:?} {}", req, e);
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        }
        Err(ProgramError(msg)) => {
            eprintln!("Error {:?} {} ", req, msg);
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    Ok(response)
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
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let state = Rc::new(RefCell::new(State::default()));

    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(state.clone(), req).await }
            }))
        }
    });

    let server = Server::bind(&addr).executor(LocalExec).serve(make_svc);
    let server = server.with_graceful_shutdown(shutdown_signal());
    println!("Listening on {}", addr);

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
