#[macro_use]
extern crate rocket;

mod api;
mod command;
mod config;
mod db;
mod user;
mod utils;

use api::SessionStore;
use command::{CommandConfigError, Commands};
use config::Config;
use db::DB;
use rocket::fairing::AdHoc;
use rocket::serde::json::serde_json;
use rocket_db_pools::{sqlx, Database};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::RwLock;

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

    // Let's go to spaaace !
    rocket::custom(figment)
        .mount("/", routes![])
        .mount(
            "/api/",
            routes![
                api::route_login,
                api::route_logout,
                api::route_commands_list,
                api::route_exec_command,
                api::route_exec_command_stream_events,
                api::route_exec_command_stream_text,
                api::route_users_list_all,
                api::route_user_create,
                api::route_user_get,
                api::route_user_update,
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
        .attach(DB::init())
        .attach(AdHoc::try_on_ignite(
            "Database schema init",
            db::init_schema,
        ))
        .manage(RwLock::new(Commands::read_or_exit(&config).await))
        .manage(SessionStore::new())
        .manage(config)
        .attach(AdHoc::on_liftoff("Startup message", move |_| {
            Box::pin(async move {
                println!("## ShellBox started on {address}:{port}");
            })
        }))
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

    #[error("{0}")]
    CommandConfigError(#[from] CommandConfigError),

    #[error("duplicate command name \"{0}\" in config")]
    DuplicateCommandName(String),

    #[error("invalid user : \"{0}\"")]
    InvalidUser(String),

    #[error("other error : {0}")]
    OtherError(String),
}
