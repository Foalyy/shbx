use crate::{
    api_response::Response,
    command::{
        Command, CommandName, CommandResult, Commands, Task, TaskId, TaskOutputMessage, Tasks,
        TasksList, UnixSignals,
    },
    config::Config,
    db::{self, DB},
    user::{AdminUser, NewUser, UpdatedUser, User, UserRole},
    Error,
};
use base64::Engine;
use rand::RngCore;
use rocket::{
    response::stream::{Event, EventStream, TextStream},
    serde::json::{self, Json},
    tokio::select,
    tokio::sync::broadcast::error::RecvError,
    tokio::sync::broadcast::Sender,
    tokio::sync::RwLock,
    Shutdown, State,
};
use rocket_db_pools::{sqlx, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use utoipa::ToSchema;

/// Sessions expire and are deleted after this delay of inactivity (in seconds)
const SESSION_TIMEOUT: u64 = 10 * 24 * 3600; // s

const DIAG_PREFIX: &str = "[shbx]";

/// Credentials sent by a user
#[derive(Deserialize, Debug, FromForm)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub permanent: bool,
}

/// An API key, either a permanent key stored in the database, or a
/// session key created and returned to the caller after a successful login
#[derive(Serialize, Default, Clone, Hash, Eq, PartialEq, Debug, ToSchema)]
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

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// List the commands available to the current user
#[utoipa::path(
    get,
    tag = "Commands",
    path = "/commands",
    context_path = "/api",
    responses(
        (status = OK, description = "List of available commands", body = Vec<Command>,
            example = json!(vec![
                Command { name: "custom_script".to_string(), label: "Launch a custom script".to_string(), exec: "/usr/bin/my_script.sh".to_string(), ..Default::default() },
                Command { name: "restart_my_service".to_string(), label: "Restart the service".to_string(), exec: "systemctl restart my_service".to_string(), ..Default::default() },
            ])
        ),
    ),
    security(("api_key" = [])),
)]
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
#[utoipa::path(
    post,
    tag = "Commands",
    path = "/commands/{command_name}",
    context_path = "/api",
    params(
        ("command_name" = String, description = "The name of the command to execute", example="restart_my_service")
    ),
    responses(
        (status = OK, description = "The command was executed successfully and returned a result", body = CommandResult, example = json!(CommandResult {
            stdout: "Service restarting...\nSuccess".to_string(),
            stderr: "".to_string(),
            exit_code: Some(0),
            signal: None,
            signal_name: None,
            execution_time: 154,
        })),
        (status = NOT_FOUND, description = "No command found with the provided name",
            body = MessageResponse, example = json!(Response::invalid_command_response())),
        (status = CONFLICT, description = "This command is configured to prevent concurrent execution, and is already running",
            body = MessageResponse, example = json!(Response::command_already_running_response())),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to execute the command",
            body = MessageResponse, example = json!(Response::command_failed_response(&std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied (os error 13)")))),
        (status = REQUEST_TIMEOUT, description = "The command was launched but had to be killed before completion because its timeout duration was reached",
            body = MessageResponseWithOutput, example = json!(Response::command_timeout_with_output_response("Service restarting...".to_string(), "".to_string(), 60000, 60012))),
        (status = 520, description = "The command was launched but the exit code could not be determined",
            body = MessageResponseWithOutput, example = json!(Response::command_failed_with_output_response("Service restarting...".to_string(), "".to_string(), "Out of memory".to_string(), 172))),
        (status = SERVICE_UNAVAILABLE, description = "The command was aborted because the server is shutting down",
            body = MessageResponseWithOutput, example = json!(Response::server_shutdown_with_output_response("Task running...".to_string(), "".to_string(), 3684))),
    ),
    security(("api_key" = [])),
)]
#[post("/commands/<command_name>")]
pub async fn route_exec_command(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    tasks: &State<Arc<RwLock<Tasks>>>,
    command_name: CommandName,
    shutdown: Shutdown,
) -> Response {
    // Try to find a valid command available to this user based on the given name
    let command = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.get_for_user(&command_name, &user)
    };

    if let Some(command) = command {
        // If the NO_CONCURRENT_EXEC parameter is set for this command, check whether it is already running
        if command.no_concurrent_exec {
            let tasks = tasks.read().await;
            if tasks.is_running(&command.name) {
                return Response::command_already_running();
            }
        }

        // Create and launch the process
        let (task_id, mut channel, start_time) = {
            // Create the task
            let mut tasks = tasks.write().await;
            let process = tasks.create(command, user.username, config);
            let task_id = process.task.id.clone();

            // Subscribe to the process's channel to receive its output messages
            let channel = process.output_channel.subscribe();

            // Launch the process
            match process.start(shutdown) {
                Ok(()) => {}
                Err(error) => {
                    std::mem::drop(tasks);
                    return Response::command_failed(&error);
                }
            }

            (task_id, channel, process.start_time)
        };

        // Task state
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code: Option<i32> = None;
        let mut signal: Option<i32> = None;
        let mut signal_name: Option<String> = None;

        // Run the task until the task terminates, then send the output and exit status to the client
        loop {
            match channel.recv().await {
                Ok(message) => {
                    match message {
                        TaskOutputMessage::TaskStarted => {}
                        TaskOutputMessage::Stdout(data) => {
                            stdout.push_str(&data);
                            stdout.push('\n');
                        }
                        TaskOutputMessage::Stderr(data) => {
                            stderr.push_str(&data);
                            stderr.push('\n');
                        }
                        TaskOutputMessage::Timeout(timeout_millis) => {
                            break Response::command_timeout_with_output(
                                stdout,
                                stderr,
                                timeout_millis,
                                start_time.unwrap().elapsed().as_millis(),
                            );
                        }
                        TaskOutputMessage::KillSignalSent => {}
                        TaskOutputMessage::ExitCode(received_exit_code, received_signal) => {
                            exit_code = received_exit_code;
                            signal = received_signal;
                            signal_name = received_signal
                                .and_then(UnixSignals::from_repr)
                                .map(|s| s.to_string());
                        }
                        TaskOutputMessage::Error(error) => {
                            break Response::command_failed_with_output(
                                stdout,
                                stderr,
                                error,
                                start_time.unwrap().elapsed().as_millis(),
                            );
                        }
                        TaskOutputMessage::ServerShutdown => {
                            break Response::server_shutdown_with_output(
                                stdout,
                                stderr,
                                start_time.unwrap().elapsed().as_millis(),
                            );
                        }
                        TaskOutputMessage::TaskTerminated => {
                            // The process terminated, send the result
                            break Response::CommandResult(Json(CommandResult {
                                stdout,
                                stderr,
                                exit_code,
                                signal,
                                signal_name,
                                execution_time: start_time.unwrap().elapsed().as_millis(),
                            }));
                        }
                    }
                }
                Err(RecvError::Closed) => {
                    // The channel closed, send the result
                    break Response::CommandResult(Json(CommandResult {
                        stdout,
                        stderr,
                        exit_code,
                        signal,
                        signal_name,
                        execution_time: start_time.unwrap().elapsed().as_millis(),
                    }));
                }
                Err(RecvError::Lagged(n)) => {
                    eprintln!("Warning : responder for task {task_id} missed {n} messages");
                }
            }
        }
    } else {
        // The client requested a command that is either invalid or not available to them
        Response::invalid_command()
    }
}

/// Launch a command without waiting for it to complete, and return its task id. As long as the task is running,
/// the task status endpoint can be used to check its progress.
#[utoipa::path(
    post,
    tag = "Commands",
    path = "/commands/{command_name}/launch",
    context_path = "/api",
    params(
        ("command_name" = String, description = "The name of the command to execute", example="restart_my_service")
    ),
    responses(
        (status = OK, description = "The command was launched successfully",
            body = MessageResponseWithTaskId, example = json!(Response::command_launched_response(TaskId::from("f99b9779-7a03-4be0-aee9-1de93ea901b8").unwrap()))),
        (status = NOT_FOUND, description = "No command found with the provided name",
            body = MessageResponse, example = json!(Response::invalid_command_response())),
        (status = CONFLICT, description = "This command is configured to prevent concurrent execution, and is already running",
            body = MessageResponse, example = json!(Response::command_already_running_response())),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to execute the command",
            body = MessageResponse, example = json!(Response::command_failed_response(&std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied (os error 13)")))),
    ),
    security(("api_key" = [])),
)]
#[post("/commands/<command_name>/launch")]
pub async fn route_exec_command_async(
    user: User,
    commands: &State<RwLock<Commands>>,
    config: &State<Config>,
    tasks: &State<Arc<RwLock<Tasks>>>,
    command_name: CommandName,
    shutdown: Shutdown,
) -> Response {
    // Try to find a valid command available to this user based on the given name
    let command = {
        let mut commands = commands.write().await;
        commands.try_reload(config).await;
        commands.get_for_user(&command_name, &user)
    };

    if let Some(command) = command {
        // If the NO_CONCURRENT_EXEC parameter is set for this command, check whether it is already running
        if command.no_concurrent_exec {
            let tasks = tasks.read().await;
            if tasks.is_running(&command.name) {
                return Response::command_already_running();
            }
        }

        // Create the task and launch the process
        let (launch_result, task_id) = {
            let mut tasks = tasks.write().await;
            let process = tasks.create(command, user.username, config);
            (process.start(shutdown), process.task.id.clone())
        };

        // Return the appropriate response to the client
        match launch_result {
            Ok(()) => Response::command_launched(task_id),
            Err(error) => Response::command_failed(&error),
        }
    } else {
        // The client requested a command that is either invalid or not available to them
        Response::invalid_command()
    }
}

/// Launch a command and start forwarding its output to the client as a stream
/// of type `text/event-stream`.
///
/// The process will keep running in the background even if the client disconnects.
/// It can be killed manually if necessary using the task-kill endpoint with the
/// task id returned in the first event.
///
/// Output example :
///
/// ```events
/// data:{"event":"task_started","task_id":"92eee54f-8f9e-49a3-bedc-f64a567ff92f"}
/// data:{"event":"stdout","task_id":"92eee54f-8f9e-49a3-bedc-f64a567ff92f","output":"Computing..."}
/// data:{"event":"stdout","task_id":"92eee54f-8f9e-49a3-bedc-f64a567ff92f","output":"Computation done"}
/// data:{"event":"task_exited","task_id":"92eee54f-8f9e-49a3-bedc-f64a567ff92f","exit_code":0,"signal":null,"signal_name":null}
/// data:{"event":"task_terminated","task_id":"92eee54f-8f9e-49a3-bedc-f64a567ff92f","execution_time":624}
/// ```
///
/// Note that the output of the child process is passed back through a pipe,
/// which means it might be buffered. For instance, Python scripts apply a
/// line-based buffering strategy when stdout is connected to a terminal, but
/// a more agressive buffering strategy when connected to a pipe, which means
/// the output might not be sent in realtime. For instance in Python, either
/// manually flush the stdout buffer with `sys.stdout.flush()`, or use `python -u`
/// to force unbuffered output. In a shebang, this may for instance translate as
/// `#!/bin/env -S python -u`.
/// Also, make sure the stream is not buffered between the server and the client
/// by a frontend reverse proxy, or by the client itself. In the case of curl,
/// consider using the -N flag.
#[utoipa::path(
    post,
    tag = "Commands",
    path = "/commands/{command_name}/stream/events",
    context_path = "/api",
    params(
        ("command_name", description = "The name of the command to execute", example="restart_my_service")
    ),
    security(("api_key" = [])),
)]
#[post("/commands/<command_name>/stream/events")]
pub async fn route_exec_command_stream_events<'a>(
    user: User,
    commands: &'a State<RwLock<Commands>>,
    config: &'a State<Config>,
    tasks: &'a State<Arc<RwLock<Tasks>>>,
    command_name: CommandName,
    shutdown: Shutdown,
) -> EventStream![Event + 'a] {
    EventStream! {
        // Try to find a valid command available to this user based on the given name
        let command = {
            let mut commands = commands.write().await;
            commands.try_reload(config).await;
            commands.get_for_user(&command_name, &user)
        };

        if let Some(command) = command {
            // If the NO_CONCURRENT_EXEC parameter is set for this command, check whether it is already running
            if command.no_concurrent_exec {
                let tasks = tasks.read().await;
                if tasks.is_running(&command.name) {
                    yield Event::json(&Response::command_already_running_response());
                    return;
                }
            }

            // Create and launch the process
            let (task_id, mut channel, start_time) = {
                // Create the task
                let mut tasks = tasks.write().await;
                let process = tasks.create(command, user.username, config);
                let task_id = process.task.id.clone();

                // Subscribe to the process's channel to receive its output messages
                let channel = process.output_channel.subscribe();

                // Launch the process
                match process.start(shutdown) {
                    Ok(()) => {}
                    Err(error) => {
                        std::mem::drop(tasks);
                        yield Event::json(&Response::command_failed_response(&error));
                        return;
                    }
                }

                (task_id, channel, process.start_time)
            };

            // Send the output of the task to the client until it disconnects or the task's channel closes
            loop {
                match channel.recv().await {
                    Ok(message) => {
                        if let Some(event) = message.into_task_event(&task_id, &start_time.unwrap()) {
                            yield Event::json(&event);
                        }
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("Warning : responder for task {task_id} missed {n} messages");
                    }
                }
            }

        } else {
            // The client requested a command that is either invalid or not available to them
            yield Event::json(&Response::invalid_command_response());
        }
    }
}

/// Launch a command and start forwarding its output to the client as a stream
/// of type `text/plain`. Stdout and stderr are forwarded as-is, and diagnostics
/// messages are inserted in the stream with the "[shbx]" prefix.
///
/// The process will keep running in the background even if the client disconnects.
/// It can be killed manually if necessary using the task-kill endpoint with the
/// task id returned in the first line.
///
/// Output example :
///
/// ```text
/// [shbx] Task started with id 92eee54f-8f9e-49a3-bedc-f64a567ff92f
/// Computing...
/// Computation done
/// [shbx] Task exited with exit code 0
/// [shbx] Task 92eee54f-8f9e-49a3-bedc-f64a567ff92f terminated after 624ms
/// ```
///
/// Note that the output of the child process is passed back through a pipe,
/// which means it might be buffered. For instance, Python scripts apply a
/// line-based buffering strategy when stdout is connected to a terminal, but
/// a more agressive buffering strategy when connected to a pipe, which means
/// the output might not be sent in realtime. For instance in Python, either
/// manually flush the stdout buffer with `sys.stdout.flush()`, or use `python -u`
/// to force unbuffered output. In a shebang, this may for instance translate as
/// `#!/bin/env -S python -u`.
/// Also, make sure the stream is not buffered between the server and the client
/// by a frontend reverse proxy, or by the client itself. In the case of curl,
/// consider using the -N flag.
#[utoipa::path(
    post,
    tag = "Commands",
    path = "/commands/{command_name}/stream/text",
    context_path = "/api",
    params(
        ("command_name", description = "The name of the command to execute", example="restart_my_service")
    ),
    security(("api_key" = [])),
)]
#[post("/commands/<command_name>/stream/text")]
pub async fn route_exec_command_stream_text<'a>(
    user: User,
    commands: &'a State<RwLock<Commands>>,
    config: &'a State<Config>,
    tasks: &'a State<Arc<RwLock<Tasks>>>,
    command_name: CommandName,
    shutdown: Shutdown,
) -> TextStream![String + 'a] {
    TextStream! {
        // Try to find a valid command available to this user based on the given name
        let command = {
            let mut commands = commands.write().await;
            commands.try_reload(config).await;
            commands.get_for_user(&command_name, &user)
        };

        if let Some(command) = command {
            // If the NO_CONCURRENT_EXEC parameter is set for this command, check whether it is already running
            if command.no_concurrent_exec {
                let tasks = tasks.read().await;
                if tasks.is_running(&command.name) {
                    yield format!("{} Error : command already running\n", DIAG_PREFIX);
                    return;
                }
            }

            // Create and launch the process
            let (task_id, mut channel, start_time) = {
                // Create the task
                let mut tasks = tasks.write().await;
                let process = tasks.create(command, user.username, config);
                let task_id = process.task.id.clone();

                // Subscribe to the process's channel to receive its output messages
                let channel = process.output_channel.subscribe();

                // Launch the process
                match process.start(shutdown) {
                    Ok(()) => {}
                    Err(error) => {
                        std::mem::drop(tasks);
                        yield format!("{} Error : command failed : {error}\n", DIAG_PREFIX);
                        return;
                    }
                }

                (task_id, channel, process.start_time)
            };

            // Send the output of the task to the client until it disconnects or the task's channel closes
            loop {
                match channel.recv().await {
                    Ok(message) => {
                        let print_prefix = !matches!(message, TaskOutputMessage::Stdout(_) | TaskOutputMessage::Stderr(_));
                        if let Some(event) = message.into_task_event(&task_id, &start_time.unwrap()) {
                            if print_prefix {
                                yield format!("{} {}\n", DIAG_PREFIX, event.to_string());
                            } else {
                                yield format!("{}\n", event.to_string());
                            }
                        }
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("Warning : responder for task {task_id} missed {n} messages");
                    }
                }
            }

        } else {
            // The client requested a command that is either invalid or not available to them
            yield format!("{} Error : invalid command\n", DIAG_PREFIX);
        }
    }
}

/// Get the list of tasks currently running
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks",
    context_path = "/api",
    responses(
        (status = OK, description = "The list of tasks currently running",
            body = Vec<Task>, example = json!(vec![Task {
                name: "restart_my_service".to_string(),
                id: TaskId::from("f99b9779-7a03-4be0-aee9-1de93ea901b8").unwrap(),
                launched_by: "john".to_string(),
                start_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            }])
        ),
    ),
    security(("api_key" = [])),
)]
#[get("/tasks")]
pub async fn route_tasks_list(user: User, tasks: &State<Arc<RwLock<Tasks>>>) -> Response {
    let tasks = tasks.read().await;
    Response::Tasks(Json(tasks.visible_to(&user).cloned().collect()))
}

/// Get the list of tasks currently running as stream of type `text/event-stream`.
///
/// The list is returned as an object indexed by task ids and containing information
/// about the associated task.
///
/// Example output when a task is launched and then terminates :
/// ```event
/// data:{}
/// data:{"74602165-755f-41b9-88d2-0494632b8c0e":{"name":"restart_my_service","id":"74602165-755f-41b9-88d2-0494632b8c0e","launched_by":"john","start_timestamp":1693949153}}
/// data:{}
/// ```
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks/stream",
    context_path = "/api",
    security(("api_key" = [])),
)]
#[get("/tasks/stream")]
pub async fn route_tasks_list_stream<'a>(
    _user: User,
    tasks: &'a State<Arc<RwLock<Tasks>>>,
    tasks_channel: &'a State<Sender<TasksList>>,
    mut end: Shutdown,
) -> EventStream![Event + 'a] {
    let mut receiver = tasks_channel.subscribe();
    EventStream! {
        // Send the current list
        {
            let tasks = tasks.read().await;
            yield Event::json(tasks.list());
        }

        // Send updates to the client as soon as they are received from the channel
        loop {
            let tasks = select! {
                tasks = receiver.recv() => match tasks {
                    Ok(tasks) => tasks,
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };
            yield Event::json(&tasks);
        }
    }
}

/// Connect to a running task and start forwarding both its past and future output
/// to the client as a stream of type `text/event-stream`.
#[utoipa::path(
    get,
    tag = "Tasks",
    path = "/tasks/{task_id}",
    context_path = "/api",
    params(
        ("task_id", description = "The id of the task to connect to", example="f99b9779-7a03-4be0-aee9-1de93ea901b8")
    ),
    security(("api_key" = [])),
)]
#[get("/tasks/<task_id>")]
pub async fn route_task_connect(
    _user: User,
    tasks: &State<Arc<RwLock<Tasks>>>,
    task_id: String,
) -> EventStream![Event + '_] {
    EventStream! {
        // Try to parse the input string as a [TaskId]
        if let Some(task_id) = TaskId::from(&task_id) {
            let (output, mut channel, start_time) = {
                let tasks = tasks.read().await;

                // Find the process corresponding to this task id, if any
                let Some(process) = tasks.get_process(&task_id) else {
                    yield Event::json(&Response::invalid_task_id_response(task_id.to_string()));
                    return;
                };

                // Get a read access on the list of past output of the past, and clone its content.
                // This is an expensive operation if the process has already been very verbose on its output
                // (stdout and stderr). However, considering the lock mechanism on the list of output messages
                // (which is mandatory to avoid a race condition between the list and the channel), the only
                // alternative would be to hold the read guard on the list for as long as it takes for the
                // backlog backlog of messages to be pushed to the client. Since the background task cannot
                // write to the list while this read lock is held, for verbose processes and slow clients,
                // this could lead to data loss in the pipe between the child process and the background task.
                let output = process.output.read().await.clone();

                // Subscribe to the output channel to receive future messages from the process
                let channel = process.output_channel.subscribe();

                (output, channel, process.start_time)
            };

            // Send the past output to the client
            for message in output {
                yield Event::json(&message.into_task_event(&task_id, &start_time.unwrap()));
            }

            // Send the output of the task to the client until it disconnects or the task's channel closes
            loop {
                match channel.recv().await {
                    Ok(message) => yield Event::json(&message.into_task_event(&task_id, &start_time.unwrap())),
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(n)) => {
                        eprintln!("Warning : responder for task {task_id} missed {n} messages");
                    }
                }
            }

        } else {
            yield Event::json(&Response::invalid_task_id_response(task_id));
        }
    }
}

/// Kill a currently-running task
#[utoipa::path(
    delete,
    tag = "Tasks",
    path = "/tasks/{task_id}",
    context_path = "/api",
    params(
        ("task_id", description = "The id of the task to kill", example="f99b9779-7a03-4be0-aee9-1de93ea901b8")
    ),
    responses(
        (status = OK, description = "The task was killed successfully",
            body = MessageResponse, example = json!(Response::task_killed_response(&TaskId::from("f99b9779-7a03-4be0-aee9-1de93ea901b8").unwrap()))),
        (status = NOT_FOUND, description = "The provided task id is malformed or does not correspond to a task",
            body = MessageResponse, example = json!(Response::invalid_task_id_response("16cf5376-b0ba-487a-8838-3c7e94ef4f1a".to_string()))),
        (status = INTERNAL_SERVER_ERROR, description = "The task could not be killed due to an internal error",
            body = MessageResponse, example = json!(Response::unable_to_kill_task_response(&TaskId::from("f99b9779-7a03-4be0-aee9-1de93ea901b8").unwrap()))),
    ),
    security(("api_key" = [])),
)]
#[delete("/tasks/<task_id>")]
pub async fn route_task_kill(
    user: User,
    tasks: &State<Arc<RwLock<Tasks>>>,
    task_id: String,
) -> Response {
    if let Some(task_id) = TaskId::from(&task_id) {
        let kill_result = {
            let mut tasks = tasks.write().await;
            tasks.kill(&task_id, &user)
        };
        match kill_result {
            Some(true) => Response::task_killed(&task_id),
            Some(false) => Response::unable_to_kill_task(&task_id),
            None => Response::invalid_task_id(task_id.to_string()),
        }
    } else {
        Response::invalid_task_id(task_id)
    }
}

/// Get the list of users (admin only)
#[utoipa::path(
    get,
    tag = "Users",
    path = "/users",
    context_path = "/api",
    responses(
        (status = OK, description = "The list of registered users",
            body = Vec<User>, example = json!(vec![User {
                username: "john".to_string(), role: UserRole::User, hashed_password: None, api_key: ApiKey("Lqk08na/PtckL/vtR5yAiqgU20/E0jex3+yk6AUCfmo=".to_string()),
                session_key: None, commands: vec!["restart_my_service".to_string(), "backup_my_data".to_string()]
            }])),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to get the list of users due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
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
#[utoipa::path(
    post,
    tag = "Users",
    path = "/users",
    context_path = "/api",
    request_body = NewUser,
    responses(
        (status = OK, description = "The user was created successfully",
            body = MessageResponse, example = json!(Response::user_created_response("john".to_string()))),
        (status = BAD_REQUEST, description = "Unable to read input data",
            body = MessageResponse, example = json!(Response::bad_request_response())),
        (status = UNPROCESSABLE_ENTITY, description = "Unable to interpret the input data as a valid user definition",
            body = MessageResponse, example = json!(Response::unprocessable_entity_with_message_response("Invalid request data : key must be a string at line 2 column 5"))),
        (status = CONFLICT, description = "A user with this username already exists",
            body = MessageResponse, example = json!(Response::user_already_exists_response("john".to_string()))),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to create the user due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
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
#[utoipa::path(
    get,
    tag = "Users",
    path = "/users/{username}",
    context_path = "/api",
    responses(
        (status = OK, description = "The user was created successfully",
        body = User, example = json!(User {
            username: "john".to_string(), role: UserRole::User, hashed_password: None, api_key: ApiKey("Lqk08na/PtckL/vtR5yAiqgU20/E0jex3+yk6AUCfmo=".to_string()),
            session_key: None, commands: vec!["restart_my_service".to_string(), "backup_my_data".to_string()]
        })),
        (status = NOT_FOUND, description = "Unable to find a user with the given username",
            body = MessageResponse, example = json!(Response::invalid_username_response("mike".to_string()))),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to create the user due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
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
        Ok(None) => Response::invalid_username(username),
        Err(error) => {
            println!("Error : unable to get a user : {error}");
            Response::internal_server_error()
        }
    }
}

/// Update a user (admin only)
#[utoipa::path(
    patch,
    tag = "Users",
    path = "/users/{username}",
    context_path = "/api",
    request_body = UpdatedUser,
    responses(
        (status = OK, description = "The user was updated successfully",
            body = MessageResponse, example = json!(Response::user_updated_response("john".to_string()))),
        (status = NOT_FOUND, description = "Unable to find a user with the given username",
            body = MessageResponse, example = json!(Response::invalid_username_response("mike".to_string()))),
        (status = BAD_REQUEST, description = "Unable to read input data",
            body = MessageResponse, example = json!(Response::bad_request_response())),
        (status = UNPROCESSABLE_ENTITY, description = "Unable to interpret the input data as a valid user update definition",
            body = MessageResponse, example = json!(Response::unprocessable_entity_with_message_response("key must be a string at line 2 column 5"))),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to update the user due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
#[patch("/users/<username>", data = "<updated_user>")]
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
#[utoipa::path(
    post,
    tag = "Users",
    path = "/users/{username}/revoke_api_key",
    context_path = "/api",
    responses(
        (status = OK, description = "The API key of the user was revoked successfully",
            body = MessageResponse, example = json!(Response::user_api_key_revoked_response("john".to_string()))),
        (status = NOT_FOUND, description = "Unable to find a user with the given username",
            body = MessageResponse, example = json!(Response::invalid_username_response("mike".to_string()))),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to revoke the API key of the user due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
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
#[utoipa::path(
    delete,
    tag = "Users",
    path = "/users/{username}",
    context_path = "/api",
    responses(
        (status = OK, description = "The user was deleted successfully",
            body = MessageResponse, example = json!(Response::user_deleted_response("john".to_string()))),
        (status = NOT_FOUND, description = "Unable to find a user with the given username",
            body = MessageResponse, example = json!(Response::invalid_username_response("mike".to_string()))),
        (status = INTERNAL_SERVER_ERROR, description = "Unable to delete the user due to an internal error",
            body = MessageResponse, example = json!(Response::internal_server_error_response())),
    ),
    security(("api_key" = [])),
)]
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
