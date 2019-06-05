#[macro_use]
extern crate serde_derive;

use actix_web::middleware::{
    identity::{CookieIdentityPolicy, Identity, IdentityService},
    Logger,
};
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer, Result};
use futures::{stream::Stream, Future};

#[derive(Deserialize, Debug)]
struct Vote {
    choice: String,
}

#[derive(Deserialize, Debug)]
struct Votes {
    choice: Vec<i8>,
}

pub fn login(id: Identity) -> Result<HttpResponse, Error> {
    id.remember("the 5th of November".to_owned());
    Ok(HttpResponse::Found()
        .header("location", "/#logged")
        .finish())
}
pub fn logout(id: Identity) -> HttpResponse {
    id.forget();
    HttpResponse::Found().header("location", "/").finish()
}

fn index(_: HttpRequest) -> HttpResponse {
    let action = "payload_id".to_owned(); // "vote", "votes", "payload"

    HttpResponse::Ok().body(format!(r#"
        <form action="{}" method="POST">
            <label for="choice_1"><input type="checkbox" name="choice" id="choice_1" value="1">Choice 1</label><br>
            <label for="choice_2"><input type="checkbox" name="choice" id="choice_2" value="2" checked>Choice 2</label><br>
            <label for="choice_3"><input type="checkbox" name="choice" id="choice_3" value="3" checked>Choice 3</label><br>

            <button type="submit">Send</button>
        </form>
        <form action="login" method="POST"><button type="submit">Login</button></form>
        <form action="logout" method="POST"><button type="submit">Logout</button></form>
        "#,
        action)
    )
}

fn vote_query_get(vote: web::Query<Vote>) -> Result<String> {
    // Query deserialize error: duplicate field `choice`, if more than one choice, else Vote { choice = "x" }
    println!("{:?}", vote);
    Ok(String::from("OK"))
}

fn vote_form_post(vote: web::Form<Vote>) -> Result<String> {
    // Parse error, if more than one choice, else Vote { choice = "x" }
    println!("{:?}", vote);
    Ok(String::from("OK"))
}

fn votes_form_post(vote: web::Form<Votes>) -> Result<String> {
    // Parse error, in any way
    println!("{:?}", vote);
    Ok(String::from("OK"))
}

fn vote_payload(body: web::Payload) -> impl Future<Item = HttpResponse, Error = Error> {
    body.map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
        .and_then(|body| {
            format!("Body {:?}!", body);
            let decoded = serde_urlencoded::from_bytes::<Vec<(String, i8)>>(&body)?;
            let vote = Votes {
                choice: decoded
                    .into_iter()
                    .filter(|(name, _v)| name == "choice")
                    .map(|(_n, value)| value)
                    .collect(),
            };
            println!("{:?}", vote);
            Ok(HttpResponse::Ok().body(format!("{:?}", vote)))
        })
}

fn vote_payload_id(
    id: Identity,
    body: web::Payload,
) -> impl Future<Item = HttpResponse, Error = Error> {
    body.map_err(Error::from)
        .fold(web::BytesMut::new(), move |mut body, chunk| {
            body.extend_from_slice(&chunk);
            Ok::<_, Error>(body)
        })
        .and_then(move |body| {
            let identity = id.identity();
            if id.identity().is_none() {
                return Ok(HttpResponse::Found().header("location", "/").finish());
            };
            format!("Body {:?}!", body);
            let decoded = serde_urlencoded::from_bytes::<Vec<(String, i8)>>(&body)?;
            let vote = Votes {
                choice: decoded
                    .into_iter()
                    .filter(|(name, _v)| name == "choice")
                    .map(|(_n, value)| value)
                    .collect(),
            };
            let email = id.identity().unwrap();
            println!("{:?}", (email, &vote));
            Ok(HttpResponse::Ok().body(format!("{:?}", vote)))
        })
}

fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .secure(false),
            ))
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/logout").route(web::post().to(logout)))
            .service(web::resource("/vote").route(web::get().to(vote_query_get)))
            .service(web::resource("/vote").route(web::post().to(vote_form_post)))
            .service(web::resource("/votes").route(web::post().to(votes_form_post)))
            .service(web::resource("/payload").route(web::post().to_async(vote_payload)))
            .service(web::resource("/payload_id").route(web::post().to_async(vote_payload_id)))
    })
    .bind("127.0.0.1:8000")
    .expect("Can not bind to port 8000")
    .run()
}
