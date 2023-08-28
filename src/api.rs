use crate::{
    command::{Command, CommandName, CommandResult, Commands, StreamCommandResult},
    config::Config,
    db::{self, DB},
    user::{AdminUser, NewUser, PlaintextPassword, UpdatedUser, User},
    Error,
};
use base64::Engine;
use rand::RngCore;
use rocket::{
    response::stream::{Event, EventStream, TextStream},
    serde::json::{self, json, Json},
    tokio::sync::RwLock,
    State,
};
use rocket_db_pools::{sqlx, Connection};
use serde::{Deserialize, Serialize};
use serde_repr::Serialize_repr;
use std::{
    collections::HashMap,
    fmt::Display,
    time::{Duration, Instant},
};
use tokio::time;
use tokio_process_stream::{Item, ProcessLineStream};
use tokio_stream::StreamExt;

/// Sessions expire and are deleted after this delay of inactivity (in seconds)
const SESSION_TIMEOUT: u64 = 3600; // s

/// Kinds of responses that the API can return to the caller
#[derive(Responder, Debug)]
#[allow(dead_code)]
pub enum Response {
    #[response(status = 400)]
    BadRequest(Json<MessageResponse>),

    #[response(status = 401)]
    MissingKeyHeader(Json<MessageResponse>),

    #[response(status = 403)]
    AccessForbidden(Json<MessageResponse>),

    #[response(status = 404)]
    NotFound(Json<MessageResponse>),

    #[response(status = 422)]
    UnprocessableEntity(Json<MessageResponse>),

    #[response(status = 500)]
    InternalServerError(Json<MessageResponse>),

    #[response(status = 200)]
    LoginSuccessful(Json<LoginSuccessfulResponse>),

    #[response(status = 403)]
    LoginFailed(Json<MessageResponse>),

    #[response(status = 200)]
    LogoutSuccessful(Json<MessageResponse>),

    #[response(status = 200)]
    CommandsList(Json<Vec<Command>>),

    #[response(status = 404)]
    InvalidCommand(Json<MessageResponse>),

    #[response(status = 500)]
    CommandFailed(Json<MessageResponse>),

    #[response(status = 408)]
    CommandTimeout(Json<MessageResponse>),

    #[response(status = 200)]
    CommandResult(Json<CommandResult>),

    #[response(status = 200)]
    UsersList(Json<Vec<User>>),

    #[response(status = 200)]
    User(Json<User>),

    #[response(status = 200)]
    UserCreated(Json<MessageResponse>),

    #[response(status = 409)]
    UserAlreadyExists(Json<MessageResponse>),

    #[response(status = 200)]
    UserUpdated(Json<MessageResponse>),

    #[response(status = 200)]
    UserApiKeyRevoked(Json<MessageResponse>),

    #[response(status = 200)]
    UserDeleted(Json<MessageResponse>),

    #[response(status = 404)]
    InvalidUsername(Json<MessageResponse>),

    #[response(status = 404)]
    InvalidUserCommand(Json<MessageResponse>),
}

#[allow(dead_code)]
impl Response {
    /// Return a BadRequest response
    pub fn bad_request() -> Self {
        Self::BadRequest(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::BadRequest,
            message: "Bad request".to_string(),
        }))
    }

    /// Return a MissingKeyHeader response
    pub fn missing_key_header() -> Self {
        Self::MissingKeyHeader(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Unauthorized,
            message: "Missing session key, please provide it as a request header named 'X-API-Key'"
                .to_string(),
        }))
    }

    /// Return a AccessForbidden response
    pub fn access_forbidden() -> Self {
        Self::AccessForbidden(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Forbidden,
            message: "Access forbidden".to_string(),
        }))
    }

    /// Return a NotFound response
    pub fn not_found() -> Self {
        Self::NotFound(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: "Not found".to_string(),
        }))
    }

    /// Return a UnprocessableEntity response
    pub fn unprocessable_entity() -> Self {
        Self::UnprocessableEntity(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: "Invalid request data".to_string(),
        }))
    }

    /// Return a UnprocessableEntity response with a custom message
    pub fn unprocessable_entity_with_message(message: &str) -> Self {
        Self::UnprocessableEntity(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: format!("Invalid request data : {message}"),
        }))
    }

    /// Return a InternalServerError response
    pub fn internal_server_error() -> Self {
        Self::InternalServerError(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::InternalServerError,
            message: "Internal server error".to_string(),
        }))
    }

    /// Return a LoginSuccessful response
    pub fn login_successful(key: ApiKey) -> Self {
        Self::LoginSuccessful(Json(LoginSuccessfulResponse::from(key)))
    }

    /// Return a LoginFailed response
    pub fn login_failed() -> Self {
        Self::LoginFailed(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Forbidden,
            message: "Invalid credentials".to_string(),
        }))
    }

    /// Return a LogoutSuccessful response
    pub fn logout_successful() -> Self {
        Self::LogoutSuccessful(Json(MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: "Logout successful".to_string(),
        }))
    }

    /// Return a InvalidCommand response
    pub fn invalid_command() -> Self {
        Self::InvalidCommand(Json(Self::invalid_command_response()))
    }

    /// Return the inner [MessageResponse] for an InvalidCommand response
    pub fn invalid_command_response() -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: "Invalid command".to_string(),
        }
    }

    /// Return a CommandFailed response
    pub fn command_failed(error: &std::io::Error) -> Self {
        Self::CommandFailed(Json(Self::command_failed_response(error)))
    }

    /// Return the inner [MessageResponse] for a CommandFailed response
    pub fn command_failed_response(error: &std::io::Error) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::InternalServerError,
            message: format!("Command failed : {error}"),
        }
    }

    /// Return a CommandTimeout response
    pub fn command_timeout(timeout: Duration) -> Self {
        Self::CommandTimeout(Json(Self::command_timeout_response(timeout)))
    }

    /// Return the inner [MessageResponse] for a CommandTimeout response
    pub fn command_timeout_response(timeout: Duration) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::RequestTimeout,
            message: format!("Command timeout after {}ms", timeout.as_millis()),
        }
    }

    /// Return a UserCreated response
    pub fn user_created(username: String) -> Self {
        Self::UserCreated(Json(MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' created successfully"),
        }))
    }

    /// Return a UserAlreadyExists response
    pub fn user_already_exists(username: String) -> Self {
        Self::UserAlreadyExists(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Conflict,
            message: format!("User '{username}' already exists"),
        }))
    }

    /// Return a UserUpdated response
    pub fn user_updated(username: String) -> Self {
        Self::UserUpdated(Json(MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' updated successfully"),
        }))
    }

    /// Return a UserApiKeyRevoked response
    pub fn user_api_key_revoked(username: String) -> Self {
        Self::UserApiKeyRevoked(Json(MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("API key of user '{username}' revoked and regenerated successfully"),
        }))
    }

    /// Return a UserDeleted response
    pub fn user_deleted(username: String) -> Self {
        Self::UserDeleted(Json(MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' deleted successfully"),
        }))
    }

    /// Return a InvalidUsername response
    pub fn invalid_username(username: String) -> Self {
        Self::InvalidUsername(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: format!("Invalid username : '{username}' not found"),
        }))
    }

    /// Return an InvalidUserCommand response
    pub fn invalid_user_command(command_name: CommandName) -> Self {
        Self::InvalidUserCommand(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: format!("Invalid request data : invalid command name : '{command_name}'"),
        }))
    }
}

/// A standardized message response returned by some of the API endpoints,
/// especially in case of errors
#[derive(Serialize, Debug)]
pub struct MessageResponse {
    result: ResultStatus,
    code: ResultCode,
    message: String,
}

/// Specifies whether this request was successful or not
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Success,
    Error,
}

/// The code of the result, the same as the HTTP response code for this request
#[derive(Serialize_repr, Debug)]
#[repr(u32)]
#[allow(dead_code)]
pub enum ResultCode {
    Ok = 200,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    UnprocessableEntity = 422,
    InternalServerError = 500,
}

/// Credentials sent by a user
#[derive(Deserialize, Debug)]
pub struct LoginCredentials {
    username: String,
    password: String,
    #[serde(default)]
    permanent: bool,
}

/// Specialized message sent after a successful login, containing the session key
#[derive(Serialize, Debug)]
pub struct LoginSuccessfulResponse {
    result: ResultStatus,
    code: ResultCode,
    key: ApiKey,
}

impl LoginSuccessfulResponse {
    /// Return a new [LoginSuccessfulResponse] based on the given key
    pub fn from(key: ApiKey) -> Self {
        Self {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            key,
        }
    }
}

/// An API key, either a permanent key stored in the database, or a
/// session key created and returned to the caller after a successful login
#[derive(Serialize, Default, Clone, Hash, Eq, PartialEq, Debug)]
#[serde(transparent)]
pub struct ApiKey(String);

impl ApiKey {
    /// Generate a new, random api key
    pub fn new() -> Self {
        let mut rand_buffer = [0; 32];
        rand::thread_rng().fill_bytes(&mut rand_buffer);
        Self(base64::engine::general_purpose::STANDARD.encode(rand_buffer))
    }
}

impl From<&str> for ApiKey {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Display for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A [User] currently logged in with some information about its current session
#[derive(Debug, Clone)]
struct Session {
    pub user: User,
    last_activity: Instant,
}

impl Session {
    /// Create a new session for the given user
    pub fn from(user: User) -> Self {
        Self {
            user,
            last_activity: Instant::now(),
        }
    }

    /// Update the last_activity field of this session
    pub fn touch(&mut self) {
        self.last_activity = Instant::now()
    }

    /// Check whether this session is expired according to [SESSION_TIMEOUT]
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed().as_secs() >= SESSION_TIMEOUT
    }
}

/// A [SessionStore] is used to store the list of [Session]s (currently logged-in [User]s)
/// referenced by their [ApiKey]
#[derive(Debug)]
pub struct SessionStore {
    sessions: RwLock<HashMap<ApiKey, Session>>,
}

impl SessionStore {
    /// Create a new [SessionStore]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new session in this [SessionStore] for the given [User]
    /// and return either the user's [ApiKey] if [permanent] is set, or
    /// a new temporary [ApiKey] otherwise
    pub async fn new_session(&self, user: User, permanent: bool) -> ApiKey {
        let key = if permanent {
            user.api_key.clone()
        } else {
            ApiKey::new()
        };
        self.new_session_with_key(user, key.clone()).await;
        key
    }

    /// Create a new session in this [SessionStore] for the given [User] and [ApiKey]
    /// if it doesn't already exist, or otherwise simply update its last_activity marker
    pub async fn new_session_with_key(&self, mut user: User, key: ApiKey) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&key) {
            session.touch();
        } else {
            user.session_key = Some(key.clone());
            sessions.insert(key, Session::from(user));
        }
    }

    /// Get a currently logged-in [User] based on the given [ApiKey]
    #[allow(dead_code)]
    pub async fn get(&self, key: &ApiKey) -> Option<User> {
        self.sessions.read().await.get(key).map(|l| l.user.clone())
    }

    /// Get a currently logged-in [User] based on the given [ApiKey],
    /// and if found, update its last_activity marker
    pub async fn get_and_touch(&self, key: &ApiKey) -> Option<User> {
        self.sessions.write().await.get_mut(key).map(|l| {
            l.touch();
            l.user.clone()
        })
    }

    /// Remove the session associated with the given [ApiKey] from the store
    /// (to logout the user)
    pub async fn delete(&self, key: &ApiKey) -> Option<User> {
        self.sessions.write().await.remove(key).map(|l| l.user)
    }

    /// Remove all the sessions of a [User] based on its username
    pub async fn delete_sessions_of(&self, username: &String) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| &session.user.username != username);
    }

    /// Update the session(s) of the given user, if any
    pub async fn update_user(&self, username: &str, updated_user: &UpdatedUser) {
        let mut sessions = self.sessions.write().await;
        for (_, session) in sessions.iter_mut() {
            if session.user.username == username {
                session.user.update_with(updated_user);
            }
        }
    }

    /// Look for old sessions inside this store that need to be removed
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| !session.is_expired());
    }
}

/// Check the credentials provided by the user and return a new session key if valid
#[post("/login", data = "<credentials>")]
pub async fn route_login(
    credentials: Json<LoginCredentials>,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    session_store: &State<SessionStore>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Try to find the user in the database
    let db_user = {
        let commands = commands.read().await;
        db::get_user(&mut db_conn, &commands, &credentials.username).await
    };
    match db_user {
        Ok(Some(user)) => {
            // A user with the given username was found in the database, check its password
            if let Some(hashed_password) = &user.hashed_password {
                if PlaintextPassword::from(credentials.password.as_str()).verify(hashed_password) {
                    let key = session_store.new_session(user, credentials.permanent).await;
                    Response::login_successful(key)
                } else {
                    Response::login_failed()
                }
            } else {
                eprintln!(
                    "Warning : user \"{}\" doesn't have a password in the database",
                    user.username
                );
                Response::login_failed()
            }
        }
        Ok(None) => Response::login_failed(),
        Err(error) => {
            eprintln!("Error : unable to get a user from the database : {error}");
            Response::login_failed()
        }
    }
}

/// Logout the current user
#[post("/logout")]
pub async fn route_logout(user: User, session_store: &State<SessionStore>) -> Response {
    // Delete this session from the store and send a confirmation to the user
    session_store
        .delete(&user.session_key.unwrap_or_default())
        .await;
    Response::logout_successful()
}

/// List the commands available to the current user
#[get("/commands")]
pub async fn route_commands_list(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
) -> Response {
    let mut available_commands = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.available_to(&user)
    };
    available_commands.sort_unstable_by_key(|k| k.name.clone());
    Response::CommandsList(Json(available_commands))
}

/// Execute a command and return its output when finished
#[post("/commands/<command_name>")]
pub async fn route_exec_command(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    command_name: CommandName,
) -> Response {
    // Try to find a valid command available to this user based on the given name
    let command = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.get_for_user(&command_name, &user)
    };

    if let Some(command) = command {
        // Maximum duration that the process can take to execute
        let timeout_duration = Duration::from_millis(command.timeout_millis);

        // Convert the Command to an executable process
        let mut process = command.into_process(config);

        // Wait for the command output, bounded by a timeout of the configured duration.
        // Because [tokio::time::timeout] drops the [Future] when it expires, and the process was
        // configured with [kill_on_drop] enabled, the child process is killed in case of a timeout.
        let timeout = time::timeout(timeout_duration, process.output()).await;

        match timeout {
            // Command executed successfully, return its output to the user
            Ok(Ok(output)) => Response::CommandResult(Json(output.into())),

            // Command failed, return the error
            Ok(Err(error)) => Response::command_failed(&error),

            // Timeout expired, the child process was killed
            Err(_) => Response::command_timeout(timeout_duration),
        }
    } else {
        Response::invalid_command()
    }
}

/// Execute a command and return the result as stream of type `text/event-stream`.
/// Note that the output of the child process is passed back through a pipe,
/// which means it might be buffered. For instance, Python scripts apply a
/// line-based buffering strategy when stdout is connected to a terminal, but
/// a more agressive buffering strategy when connected to a pipe, which means
/// the output might not be sent in realtime. In Python's case, either manually
/// flush the stdout buffer with `sys.stdout.flush()`, or use `python -u` to
/// force unbuffered output. In a shebang, this may for instance translate as
/// `#!/bin/env -S python -u`.
/// Also, make sure the stream is not buffered by a frontend reverse proxy.
#[post("/commands/<command_name>/stream/events")]
pub async fn route_exec_command_stream_events<'a>(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &'a State<Config>,
    command_name: CommandName,
) -> EventStream![Event + 'a] {
    // Try to find a valid command available to this user based on the given name
    let command = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.get_for_user(&command_name, &user)
    };

    EventStream! {
        if let Some(command) = command {
            // Maximum duration that the process can take to execute
            let timeout_duration = Duration::from_millis(command.timeout_millis);

            // Convert the Command to an executable process
            let mut process = command.into_process(config);

            // Create a simple sleep task that will be used as a timeout
            let timeout = time::sleep(timeout_duration);
            tokio::pin!(timeout);

            // Try to spawn the child process
            match process.spawn() {
                Ok(child) => {
                    // Get the output of the child process as a Stream
                    let mut cmd_stream = ProcessLineStream::from(child);

                    loop {
                        tokio::select! {
                            item = cmd_stream.next() => {
                                // The child sent an event :
                                match item {
                                    // - some output to stdout or stderr
                                    Some(Item::Stdout(data)) => yield Event::json(&StreamCommandResult::Stdout(data)),
                                    Some(Item::Stderr(data)) => yield Event::json(&StreamCommandResult::Stderr(data)),

                                    // - an exit status
                                    Some(Item::Done(Ok(status))) => yield Event::json(&StreamCommandResult::ExitCode(status.code())),
                                    Some(Item::Done(Err(error))) => yield Event::json(&StreamCommandResult::Error(format!("{error}"))),

                                    // - (no more events available because the process finished)
                                    None => break,
                                }
                            }
                            () = &mut timeout => {
                                // Timeout expired
                                yield Event::json(&Response::command_timeout_response(timeout_duration));
                                break;
                            }
                        }
                    }
                    // When the loop returns, [child] is dropped, which ensures it is killed because [kill_on_drop] is set when
                    // the process is created
                }

                // Command failed, return the error
                Err(error) => yield Event::json(&Response::command_failed_response(&error)),
            }
        } else {
            yield Event::json(&Response::invalid_command_response());
        }
    }
}

/// Execute a command and return the result as stream of type `text/plain`.
/// See the warning regarding buffering in [route_exec_command_async_event].
#[post("/commands/<command_name>/stream/text")]
pub async fn route_exec_command_stream_text<'a>(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &'a State<Config>,
    command_name: CommandName,
) -> TextStream![String + 'a] {
    // Try to find a valid command available to this user based on the given name
    let command = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.get_for_user(&command_name, &user)
    };

    TextStream! {
        if let Some(command) = command {
            // Maximum duration that the process can take to execute
            let timeout_duration = Duration::from_millis(command.timeout_millis);

            // Convert the Command to an executable process
            let mut process = command.into_process(config);

            // Create a simple sleep task that will be used as a timeout
            let timeout = time::sleep(timeout_duration);
            tokio::pin!(timeout);

            // Try to spawn the child process
            match process.spawn() {
                Ok(child) => {
                    // Get the output of the child process as a Stream
                    let mut cmd_stream = ProcessLineStream::from(child);

                    loop {
                        tokio::select! {
                            item = cmd_stream.next() => {
                                // The child sent an event :
                                match item {
                                    // - some output to stdout or stderr
                                    Some(Item::Stdout(text)) => yield format!("{text}\n"),
                                    Some(Item::Stderr(text)) => yield format!("{text}\n"),

                                    // - an exit status
                                    Some(Item::Done(Ok(status))) => yield format!("{}\n", json!(&StreamCommandResult::ExitCode(status.code()))),
                                    Some(Item::Done(Err(error))) => yield format!("{}\n", json!(&StreamCommandResult::Error(format!("{error}")))),

                                    // - (no more events available because the process finished)
                                    None => break,
                                }
                            }
                            () = &mut timeout => {
                                // Timeout expired
                                yield format!("{}\n", json!(&Response::command_timeout_response(timeout_duration)));
                                break;
                            }
                        }
                    }
                    // When the loop returns, [child] is dropped, which ensures it is killed because [kill_on_drop] is set when
                    // the process is created
                }

                // Command failed, return the error
                Err(error) => yield format!("{}\n", json!(&Response::command_failed_response(&error))),
            }
        } else {
            yield format!("{}\n", json!(Response::invalid_command_response()));
        }
    }
}

/// Get the list of users (admin only)
#[get("/users")]
pub async fn route_users_list_all(
    _user: AdminUser,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Get the list of users from the database
    let users = {
        let commands = commands.read().await;
        db::list_users(&mut db_conn, &commands).await
    };
    match users {
        Ok(users) => Response::UsersList(Json(users)),
        Err(error) => {
            println!("Error : unable to get the list of users : {error}");
            Response::internal_server_error()
        }
    }
}

/// Create a user (admin only)
#[post("/users", data = "<new_user>")]
pub async fn route_user_create(
    _user: AdminUser,
    new_user: Result<Json<NewUser>, json::Error<'_>>,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Check whether the provided data was successfully parsed as a NewUser
    match new_user {
        // We have a NewUser, check that it is valid before trying to insert it into the database
        Ok(new_user) => {
            let username = new_user.username.clone();

            // Check that the provided command names are valid
            {
                let commands = commands.read().await;
                if let Err(error) = commands.check_user_commands(&new_user.commands) {
                    return Response::invalid_user_command(error);
                }
            }

            match db::insert_user(&mut db_conn, new_user.into_inner()).await {
                // The user was successfully added into the database
                Ok(_) => Response::user_created(username),

                // Unable to add the user
                Err(error) => match error {
                    // Check whether this is a SQLITE_CONSTRAINT_PRIMARYKEY error (see https://www.sqlite.org/rescode.html#constraint_primarykey),
                    // which means a user with this username already exists, to return an appropriate error.
                    // Note: when `rocket_db_pools` updates its `sqlx` dependency to v0.7, this should be replaced
                    // with `sqlx::error::DatabaseError::is_unique_violation()`
                    Error::DatabaseError(sqlx::Error::Database(error))
                        if error.code().unwrap_or_default() == "1555" =>
                    {
                        Response::user_already_exists(username)
                    }

                    // Another database error happened
                    _ => {
                        println!("Error : unable to create a user : {error}");
                        Response::internal_server_error()
                    }
                },
            }
        }

        // Json parser error
        Err(json::Error::Parse(_, error)) => {
            Response::unprocessable_entity_with_message(&error.to_string())
        }

        // Unable to read input data, or any other error
        _ => Response::bad_request(),
    }
}

/// Get a specific user based on its username (admin only)
#[get("/users/<username>")]
pub async fn route_user_get(
    _user: AdminUser,
    username: String,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Get the user from the database
    let user = {
        let commands = commands.read().await;
        db::get_user(&mut db_conn, &commands, &username).await
    };
    match user {
        Ok(Some(user)) => Response::User(Json(user)),
        Ok(None) => Response::not_found(),
        Err(error) => {
            println!("Error : unable to get a user : {error}");
            Response::internal_server_error()
        }
    }
}

/// Update a user (admin only)
#[post("/users/<username>", data = "<updated_user>")]
pub async fn route_user_update(
    _user: AdminUser,
    username: String,
    updated_user: Result<Json<UpdatedUser>, json::Error<'_>>,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    session_store: &State<SessionStore>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Check whether the provided data was successfully parsed as a UpdatedUser
    match updated_user {
        // We have a UpdatedUser, check that it is valid before trying to send it to the database
        Ok(updated_user) => {
            // Check that the provided command names (if any) are valid
            {
                let commands = commands.read().await;
                if let Some(updated_commands) = &updated_user.commands {
                    if let Err(error) = commands.check_user_commands(updated_commands) {
                        return Response::invalid_user_command(error);
                    }
                }
            }

            let update_result = db::update_user(
                &mut db_conn,
                username.clone(),
                updated_user.clone().into_inner(),
            )
            .await;
            match update_result {
                // The user was successfully updated in the database
                Ok(_) => {
                    // Update the user in the session store
                    session_store.update_user(&username, &updated_user).await;

                    Response::user_updated(username)
                }

                // No user with the given username was found
                Err(Error::InvalidUser(username)) => Response::invalid_username(username),

                // Another error
                Err(error) => {
                    println!("Error : unable to update a user : {error}");
                    Response::internal_server_error()
                }
            }
        }

        // Json parser error
        Err(json::Error::Parse(_, error)) => {
            Response::unprocessable_entity_with_message(&error.to_string())
        }

        // Unable to read input data, or any other error
        _ => Response::bad_request(),
    }
}

/// Revoke the API key of a user and generate a new one (admin only)
#[post("/users/<username>/revoke_api_key")]
pub async fn route_user_revoke_api_key(
    _user: AdminUser,
    username: String,
    session_store: &State<SessionStore>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Remove all current sessions of this user
    session_store.delete_sessions_of(&username).await;

    let revoke_result = db::revoke_user_api_key(&mut db_conn, username.clone()).await;
    match revoke_result {
        // The user was successfully updated in the database
        Ok(_) => Response::user_api_key_revoked(username),

        // No user with the given username was found
        Err(Error::InvalidUser(username)) => Response::invalid_username(username),

        // Another error
        Err(error) => {
            println!("Error : unable to revoke a user' API key : {error}");
            Response::internal_server_error()
        }
    }
}

/// Delete a user (admin only)
#[delete("/users/<username>")]
pub async fn route_user_delete(
    _user: AdminUser,
    username: String,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    mut db_conn: Connection<DB>,
) -> Response {
    // Reload the commands config file if necessary
    {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
    }

    // Delete the user from the database
    match db::delete_user(&mut db_conn, username.clone()).await {
        // The user was successfully deleted from the database
        Ok(_) => Response::user_deleted(username),

        // No user with the given username was found
        Err(Error::InvalidUser(username)) => Response::invalid_username(username),

        // Another error
        Err(error) => {
            println!("Error : unable to delete a user : {error}");
            Response::internal_server_error()
        }
    }
}

/// Unauthorized (missing key header)
#[catch(400)]
pub fn catcher_bad_request() -> Response {
    Response::bad_request()
}

/// Unauthorized (missing key header)
#[catch(401)]
pub fn catcher_unauthorized() -> Response {
    Response::missing_key_header()
}

/// Forbidden (missing key header)
#[catch(403)]
pub fn catcher_forbidden() -> Response {
    Response::access_forbidden()
}

/// Not found
#[catch(404)]
pub fn catcher_not_found() -> Response {
    Response::not_found()
}

/// Unprocessable entity
#[catch(422)]
pub fn catcher_unprocessable_entity() -> Response {
    Response::unprocessable_entity()
}

/// Internal server error
#[catch(500)]
pub fn catcher_internal_server_error() -> Response {
    Response::internal_server_error()
}
