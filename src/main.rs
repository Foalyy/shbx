#[macro_use]
extern crate rocket;

mod api;
mod api_response;
mod command;
mod config;
mod db;
mod openapi_doc;
mod user;
mod utils;

use api::SessionStore;
use api_response::Response;
use command::{CommandConfigError, Commands, TaskId, Tasks, TasksList};
use config::Config;
use db::DB;
use openapi_doc::ApiDoc;
use rocket::{
    fairing::AdHoc,
    form::Form,
    fs::FileServer,
    http::{Cookie, CookieJar},
    request::FlashMessage,
    response::{Flash, Redirect},
    serde::json::serde_json,
    tokio::sync::{broadcast::channel, RwLock},
    State,
};
use rocket_db_pools::{sqlx, Connection, Database};
use rocket_dyn_templates::{context, Template};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use user::PlaintextPassword;
use utoipa::OpenApi;
use utoipa_rapidoc::RapiDoc;
use utoipa_swagger_ui::SwaggerUi;

use crate::api::LoginCredentials;
use crate::user::User;

#[launch]
async fn rocket() -> _ {
    // Try to read the config file
    let config = Config::read_or_exit();
    let address = config.address.clone();
    let ip_addr = config
        .address
        .parse::<IpAddr>()
        .map_err(|e| {
            eprintln!(
                "Error : invalid value for ADDRESS in {} : {}",
                config::FILENAME,
                e
            );
            std::process::exit(-1);
        })
        .unwrap();
    let port = config.port;

    // Send some of the settings to Rocket
    let figment = rocket::Config::figment()
        .merge(("ident", "ShellBox"))
        .merge(("secret_key", config::get_secret_key_or_exit()))
        .merge(("address", ip_addr))
        .merge(("port", config.port))
        .merge(("databases.shbx.url", &config.database_path));

    // Create a channel to broadcast updates of the tasks list. This will be managed in a
    // Rocket State and can be subscribed to by async responders, mainly [route_tasks_list_stream].
    let tasks_updates_channel = channel::<TasksList>(1).0;

    // Create the global struct that manages the list of running tasks. This is wrapped in an Arc
    // in order to give ownership of the struct to Rocket (in a managed State), while keeping a weak
    // pointer on it for the monitoring async task that handles events coming from child processes.
    let tasks = Arc::new(RwLock::new(Tasks::new(tasks_updates_channel.clone())));
    Tasks::start_monitoring_task(Arc::downgrade(&tasks)).await;

    // Let's go to spaaace !
    rocket::custom(figment)
        .mount("/", routes![index, route_login, route_logout])
        .mount(
            "/api/",
            routes![
                api::route_commands_list,
                api::route_exec_command,
                api::route_exec_command_async,
                api::route_exec_command_stream_events,
                api::route_exec_command_stream_text,
                api::route_tasks_list,
                api::route_tasks_list_stream,
                api::route_task_connect,
                api::route_task_kill,
                api::route_task_send_signal,
                api::route_users_list_all,
                api::route_user_create,
                api::route_user_get,
                api::route_user_update,
                api::route_user_revoke_api_key,
                api::route_user_delete,
            ],
        )
        .register(
            "/api/",
            catchers![
                api::catcher_bad_request,
                api::catcher_unauthorized,
                api::catcher_forbidden,
                api::catcher_not_found,
                api::catcher_unprocessable_entity,
                api::catcher_internal_server_error,
            ],
        )
        .mount("/static", FileServer::from("static/").rank(0))
        .mount(
            "/",
            SwaggerUi::new("/api/doc/<_..>").url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
        .mount(
            "/",
            RapiDoc::new("/api-docs/openapi.json").path("/api/rapidoc"),
        )
        .attach(DB::init())
        .attach(AdHoc::try_on_ignite(
            "Database schema init",
            db::init_schema,
        ))
        .manage(RwLock::new(Commands::read_or_exit(&config).await))
        .manage(SessionStore::new())
        .manage(tasks)
        .manage(tasks_updates_channel)
        .manage(config)
        .attach(Template::fairing())
        .attach(AdHoc::on_liftoff("Startup message", move |_| {
            Box::pin(async move {
                println!("ShellBox started on {address}:{port}");
                println!("API documentation available on /api/doc and /api/rapidoc");
            })
        }))
}

/// Web UI : return the main template
#[get("/")]
fn index(flash: Option<FlashMessage<'_>>) -> Template {
    Template::render(
        "main",
        context! {
            flash: flash,
            login_url: format!("{}", uri!(route_login())),
            logout_url: format!("{}", uri!(route_logout())),
        },
    )
}

/// Check the credentials provided by the user and, if valid, set a
/// new session key in the private cookies
#[post("/login", data = "<credentials>")]
pub async fn route_login(
    credentials: Form<LoginCredentials>,
    commands: &State<RwLock<Commands>>,
    session_store: &State<SessionStore>,
    cookies: &CookieJar<'_>,
    mut db_conn: Connection<DB>,
) -> Flash<Redirect> {
    let redirect = Redirect::to(uri!(index()));

    // Try to find the user in the database
    let db_user = {
        let commands = commands.read().await;
        db::get_user(&mut db_conn, &commands, &credentials.username).await
    };
    match db_user {
        Ok(Some(user)) => {
            // A user with the given username was found in the database, check the password
            if let Some(hashed_password) = &user.hashed_password {
                if PlaintextPassword::from(credentials.password.as_str()).verify(hashed_password) {
                    // The given password is valid : create the session and add it to the client' cookies
                    let key = session_store.new_session(user, credentials.permanent).await;
                    cookies.add_private(Cookie::new("api_key", key.to_string()));
                    Flash::success(redirect, format!("Welcome {}", credentials.username))
                } else {
                    Flash::error(redirect, "Invalid credentials")
                }
            } else {
                eprintln!(
                    "Warning : user \"{}\" doesn't have a password in the database",
                    user.username
                );
                Flash::error(redirect, "Invalid credentials")
            }
        }
        Ok(None) => Flash::error(redirect, "Invalid credentials"),
        Err(error) => {
            eprintln!("Error : unable to get a user from the database : {error}");
            Flash::error(redirect, "Invalid credentials")
        }
    }
}

/// Logout the current user
#[post("/logout")]
pub async fn route_logout(
    user: User,
    session_store: &State<SessionStore>,
    cookies: &CookieJar<'_>,
) -> Response {
    // Delete this session from the store, delete the cookie, and send a confirmation to the user
    session_store
        .delete(&user.session_key.unwrap_or_default())
        .await;
    cookies.remove_private(Cookie::named("api_key"));
    Response::logout_successful()
}

/// General type used to standardize errors across the crate
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid request : \"{0}\"")]
    InvalidRequestError(PathBuf),

    #[error("error accessing the file at {1} : {0}")]
    FileError(io::Error, PathBuf),

    #[error("unable to parse the input as a TOML file : {0}")]
    TomlParserError(#[from] toml::de::Error),

    #[error("unable to parse or encode the given data as JSON : {0}")]
    JsonError(#[from] serde_json::error::Error),

    #[error("database error : {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("enum parsing error : {0}")]
    EnumParserError(#[from] strum::ParseError),

    #[error("commands config file \"{0}\" not found, please check COMMANDS_PATH in the main config file")]
    CommandsConfigFileNotFound(PathBuf),

    #[error("invalid working dir \"{0}\", please check WORKING_DIR in the main config file : {1}")]
    InvalidConfigWorkingDir(PathBuf, io::Error),

    #[error("working dir \"{0}\" is not a valid directory, please check WORKING_DIR in the main config file")]
    ConfigWorkingDirNotADir(PathBuf),

    #[error("invalid shell \"{0}\"")]
    ConfigInvalidShell(String),

    #[error("{0}")]
    CommandConfigError(#[from] CommandConfigError),

    #[error("duplicate command name \"{0}\" in config")]
    DuplicateCommandName(String),

    #[error("invalid user : \"{0}\"")]
    InvalidUser(String),

    #[error("invalid task id : \"{0}\"")]
    InvalidTaskId(TaskId),

    #[error("error : : {0}")]
    IoError(#[from] std::io::Error),

    #[error("other error : {0}")]
    OtherError(String),
}
