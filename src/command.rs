use crate::{
    api_response::ResultCode,
    config::Config,
    user::{User, UserRole},
    utils, Error,
};
use is_executable::IsExecutable;
use rocket::{
    tokio::{
        fs, process,
        sync::{broadcast, mpsc, oneshot, RwLock},
        task::JoinHandle,
        time,
    },
    Shutdown,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    ops::Deref,
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use strum::{Display, FromRepr};
use tokio_process_stream::{Item, ProcessLineStream};
use tokio_stream::StreamExt;
use unix_users::os::unix::UserExt;
use utoipa::ToSchema;
use uuid::Uuid;

pub type CommandName = String;

/// A command as written in the config file
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CommandConfig {
    pub name: CommandName,
    pub label: Option<String>,
    pub command_group: Option<String>,
    pub shell: Option<bool>,
    pub timeout_millis: Option<u64>,
    pub no_timeout: Option<bool>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub exec: String,
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    pub no_concurrent_exec: bool,
}

/// A command that ShellBox can execute
#[derive(Clone, Serialize, Debug, ToSchema, Default)]
pub struct Command {
    /// Unique identifier for the command
    #[schema(value_type = String)]
    pub name: CommandName,
    /// Human-readable label displayed to the user
    pub label: String,
    /// Optional group that this command belongs to
    pub command_group: Option<String>,
    /// Execute this command inside a shell
    #[serde(skip)]
    pub shell: bool,
    #[serde(skip)]
    pub timeout_millis: Option<u64>,
    #[serde(skip)]
    pub user: Option<unix_users::User>,
    #[serde(skip)]
    pub group: Option<unix_users::Group>,
    /// Command to execute
    pub exec: String,
    #[serde(skip)]
    pub cmd: CommandExec,
    #[serde(skip)]
    pub working_dir: PathBuf,
    #[serde(skip)]
    pub no_concurrent_exec: bool,
    #[serde(rename = "working_dir", skip_serializing_if = "Option::is_none")]
    pub explicit_working_dir: Option<PathBuf>,
}

/// Path and arguments of an executable command
#[derive(Clone, Debug, Default)]
pub struct CommandExec {
    pub path: PathBuf,
    pub args: Vec<String>,
}

impl Command {
    /// Try to build a valid [Command] from the given [CommandConfig]
    pub fn from_config(
        command_config: &CommandConfig,
        config: &Config,
    ) -> Result<Self, CommandConfigError> {
        // Check the command name
        let name = command_config.name.clone();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(CommandConfigError::InvalidName(name));
        }

        // Get the label if one is specified, or default to the command name
        let label = command_config.label.clone().unwrap_or_else(|| name.clone());

        // Check the user and group, if any
        let user = command_config
            .user
            .as_ref()
            .map(|user_name| {
                unix_users::get_user_by_name(&user_name)
                    .ok_or_else(|| CommandConfigError::InvalidUser(user_name.clone()))
            })
            .transpose()?;
        let group = command_config
            .group
            .as_ref()
            .map(|group_name| {
                unix_users::get_group_by_name(&group_name)
                    .ok_or_else(|| CommandConfigError::InvalidGroup(group_name.clone()))
            })
            .transpose()?;

        // Check that the specified exec path is valid and refers to an executable file
        let exec = command_config.exec.clone();
        let mut exec_path_split = utils::split_line(&command_config.exec);
        let mut exec_path_cmd = PathBuf::from(
            exec_path_split
                .get(0)
                .ok_or_else(|| CommandConfigError::EmptyPath(name.clone()))?,
        );
        exec_path_split.remove(0);
        let exec_path_args = exec_path_split;
        if exec_path_cmd.is_absolute() {
            exec_path_cmd = exec_path_cmd.canonicalize().map_err(|io_error| {
                CommandConfigError::InvalidPath(name.clone(), exec_path_cmd.clone(), io_error)
            })?;
            if !exec_path_cmd.exists() {
                return Err(CommandConfigError::ExecPathDoesNotExist(
                    name,
                    exec_path_cmd,
                ));
            }
            if !exec_path_cmd.is_file() {
                return Err(CommandConfigError::ExecIsNotAFile(name, exec_path_cmd));
            }
            if !exec_path_cmd.is_executable() {
                return Err(CommandConfigError::ExecPathIsNotExecutable(
                    name,
                    exec_path_cmd,
                ));
            }
        }

        // Compute the working dir with the following order or priority :
        // - the working directory specified for this command, if any
        // - the directory containing the exec command, if any
        // - the default working directory specified in the global config
        //      (which, if not set, defaults to the system's temp directory, such as /tmp on Unix)
        // and check that it is valid
        let exec_path_parent = match exec_path_cmd.parent() {
            Some(p) if p != PathBuf::new() => Some(p.to_path_buf()),
            _ => None,
        };
        let mut working_dir = command_config
            .working_dir
            .clone()
            .or(exec_path_parent)
            .unwrap_or_else(|| config.working_dir.clone());
        if working_dir.is_relative() {
            let mut cmd_working_dir = config.working_dir.clone();
            cmd_working_dir.push(working_dir);
            working_dir = cmd_working_dir;
        }
        working_dir = working_dir
            .canonicalize()
            .map_err(|e| CommandConfigError::InvalidWorkingDir(name.clone(), working_dir, e))?;
        if !working_dir.exists() {
            return Err(CommandConfigError::WorkingDirDoesNotExist(
                name,
                working_dir,
            ));
        }
        if !working_dir.is_dir() {
            return Err(CommandConfigError::WorkingDirIsNotADir(name, working_dir));
        }

        // Optional timeout
        let timeout_millis = if command_config.no_timeout.unwrap_or(false) {
            None
        } else {
            Some(
                command_config
                    .timeout_millis
                    .unwrap_or(config.timeout_millis),
            )
        };

        Ok(Self {
            name,
            label,
            command_group: command_config.command_group.clone(),
            shell: command_config.shell.unwrap_or(false),
            timeout_millis,
            user,
            group,
            exec,
            cmd: CommandExec {
                path: exec_path_cmd,
                args: exec_path_args,
            },
            working_dir,
            no_concurrent_exec: command_config.no_concurrent_exec,
            explicit_working_dir: command_config.working_dir.clone(),
        })
    }

    /// Consume this [Command] and convert it into a [process::Command] ready to be executed.
    pub fn into_process(self, config: &Config) -> process::Command {
        let mut cmd = if !self.shell {
            // Run the command directly
            let mut cmd = process::Command::new(self.cmd.path);
            cmd.args(self.cmd.args);
            cmd
        } else {
            // Run the command in a shell
            let mut cmd = process::Command::new(config.shell_parsed.0.clone());
            cmd.args(config.shell_parsed.1.clone());
            cmd.arg(self.exec);
            cmd
        };
        if let Some(user) = self.user {
            cmd.uid(user.uid());
            cmd.env("HOME", user.home_dir());
            cmd.env("USER", user.name());
            cmd.env("LOGNAME", user.name());
        }
        if let Some(group) = self.group {
            cmd.gid(group.gid());
        }
        cmd.current_dir(self.working_dir);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);
        cmd
    }
}

/// Errors that can happen when trying to build a [Command] object from a [CommandConfig]
#[derive(thiserror::Error, Debug)]
pub enum CommandConfigError {
    #[error("invalid command name \"{0}\", only letters, digits and underscores are allowed")]
    InvalidName(String),

    #[error("invalid user \"{0}\"")]
    InvalidUser(String),

    #[error("invalid group \"{0}\"")]
    InvalidGroup(String),

    #[error("empty exec path for command \"{0}\"")]
    EmptyPath(CommandName),

    #[error("invalid path \"{1}\" for command \"{0}\" : {2}")]
    InvalidPath(CommandName, PathBuf, std::io::Error),

    #[error("exec path \"{1}\" does not exist for command \"{0}\"")]
    ExecPathDoesNotExist(CommandName, PathBuf),

    #[error("exec path \"{1}\" is not a file for command \"{0}\"")]
    ExecIsNotAFile(CommandName, PathBuf),

    #[error("exec path \"{1}\" is not an executable file for command \"{0}\"")]
    ExecPathIsNotExecutable(CommandName, PathBuf),

    #[error("invalid working dir \"{1}\" for command \"{0}\" : {2}")]
    InvalidWorkingDir(CommandName, PathBuf, std::io::Error),

    #[error("working dir \"{1}\" does not exist for command \"{0}\"")]
    WorkingDirDoesNotExist(CommandName, PathBuf),

    #[error("working dir \"{1}\" is not a directory for command \"{0}\"")]
    WorkingDirIsNotADir(CommandName, PathBuf),
}

/// A manageable container for a list of [Command]s
#[derive(Debug)]
pub struct Commands {
    commands_index: Vec<CommandName>,
    commands: HashMap<CommandName, Command>,
    modified_time: SystemTime,
}

impl Commands {
    /// Create a new commands container
    pub async fn read_or_exit(config: &Config) -> Self {
        let mut commands = Self {
            commands_index: Vec::new(),
            commands: HashMap::new(),
            modified_time: std::time::UNIX_EPOCH,
        };
        match commands.reload(config).await {
            Ok(_) => {
                println!(
                    "Read {} command{} from {}",
                    commands.len(),
                    if commands.len() >= 2 { "s" } else { "" },
                    config.commands_path.display()
                );
                commands
            }
            Err(error) => {
                eprintln!(
                    "Error, unable to load the commands config file \"{}\" : {error}",
                    config.commands_path.display()
                );
                std::process::exit(-1);
            }
        }
    }

    /// Reload the commands config file if it was updated
    pub async fn reload(&mut self, config: &Config) -> Result<bool, Error> {
        let path = &config.commands_path;

        // Read the modified time of the commands config file
        let metadata = fs::metadata(path)
            .await
            .map_err(|e| Error::FileError(e, PathBuf::from(path)))?;
        let file_modified_time = metadata
            .modified()
            .map_err(|e| Error::FileError(e, PathBuf::from(path)))?;

        // Check if the file was modified
        if self.modified_time != file_modified_time {
            // Try to parse the content of the file as a CommandsConfig
            let file_content = fs::read_to_string(&path)
                .await
                .map_err(|e| Error::FileError(e, PathBuf::from(path)))?;
            let commands_config: CommandsConfig = toml::from_str(file_content.as_str())?;

            // Check and map the parsed CommandsConfig to a HashMap of Command's indexed by the command name
            let mut commands_index = Vec::new();
            let mut commands = HashMap::new();
            for command_config in &commands_config.commands {
                let command = Command::from_config(command_config, config)?;
                commands_index.push(command.name.clone());
                let previous_entry = commands.insert(command.name.clone(), command);
                if let Some(previous_entry) = previous_entry {
                    return Err(Error::DuplicateCommandName(previous_entry.name));
                }
            }

            // Update self
            self.commands_index = commands_index;
            self.commands = commands;
            self.modified_time = file_modified_time;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn try_reload(&mut self, config: &Config) {
        match self.reload(config).await {
            Ok(true) => println!("Commands config file updated"),
            Ok(false) => {} // Not changed
            Err(error) => eprintln!("Error, unable to reload the commands config file : {error}"),
        }
    }

    /// Check if the given list of commands contains only valid names
    pub fn check_user_commands(&self, user_commands: &[CommandName]) -> Result<(), CommandName> {
        match user_commands.iter().find(|name| !self.contains_key(*name)) {
            Some(name) => Err(name.clone()),
            None => Ok(()),
        }
    }

    /// Get the list of command available to the given [User]
    pub fn available_to(&self, user: &User) -> Vec<Command> {
        self.commands_index
            .iter()
            .filter_map(|name| {
                if user.role == UserRole::Admin || user.commands.contains(name) {
                    self.commands.get(name).cloned()
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get a command based on its name and the user that requests it
    pub fn get_for_user(&self, command_name: &CommandName, user: &User) -> Option<Command> {
        if user.role == UserRole::Admin || user.commands.contains(command_name) {
            if let Some(command) = self.commands.get(command_name) {
                return Some(command.clone());
            }
        }
        None
    }
}

impl Deref for Commands {
    type Target = HashMap<CommandName, Command>;

    fn deref(&self) -> &Self::Target {
        &self.commands
    }
}

/// A list of [CommandConfig]s, as deserialized from the dedicated TOML config file
#[derive(Deserialize, Debug)]
pub struct CommandsConfig {
    #[serde(rename = "command")]
    commands: Vec<CommandConfig>,
}

/// Result of a command that was executed by a user
#[derive(Serialize, Debug, ToSchema)]
pub struct CommandResult {
    /// Output that the command printed on stdout
    pub stdout: String,
    /// Output that the command printed on stderr
    pub stderr: String,
    /// Exit code returned by the command, if any
    pub exit_code: Option<i32>,
    /// Signal that terminated the command, if any
    pub signal: Option<i32>,
    /// Name of the signal that terminated the command, if any
    pub signal_name: Option<String>,
    /// Total time taken by the command to execute, in milliseconds
    pub execution_time: u128,
}

/// Item in a result stream of a command that was executed by a user
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum TaskEvent {
    TaskStarted(TaskStarted),
    Stdout(TaskStdout),
    Stderr(TaskStderr),
    TaskTimeout(TaskTimeout),
    TaskExited(TaskExited),
    KillSignalSent(KillSignalSent),
    SignalSent(SignalSent),
    TaskKilled(TaskKilled),
    UnableToKillTask(UnableToKillTask),
    TaskTerminated(TaskTerminated),
    ServerShutdown(ServerShutdown),
    Error(TaskError),
}

impl ToString for TaskEvent {
    /// Represent this event as text
    fn to_string(&self) -> String {
        match self {
            TaskEvent::TaskStarted(event) => {
                format!("Task started with id {}", event.task_id)
            }
            TaskEvent::Stdout(event) => event.output.to_string(),
            TaskEvent::Stderr(event) => event.output.to_string(),
            TaskEvent::TaskTimeout(event) => {
                format!(
                    "Task timeout after reaching the maximum execution time of {}ms",
                    event.timeout_millis
                )
            }
            TaskEvent::TaskExited(event) => {
                if let Some(signal_name) = event.signal_name.as_ref() {
                    format!("Task exited with signal {signal_name}",)
                } else if let Some(signal) = event.signal {
                    format!("Task exited with signal {signal}",)
                } else if let Some(exit_code) = event.exit_code {
                    format!("Task exited with exit code {exit_code}",)
                } else {
                    "Task exited without an exit code".to_string()
                }
            }
            TaskEvent::KillSignalSent(_) => "Kill signal sent".to_string(),
            TaskEvent::SignalSent(event) => format!("Signal {} sent", event.signal),
            TaskEvent::TaskKilled(_) => "Task killed".to_string(),
            TaskEvent::UnableToKillTask(event) => {
                format!("Error, unable to kill the task : {}", event.message)
            }
            TaskEvent::TaskTerminated(event) => format!(
                "Task {} terminated after {}ms",
                event.task_id, event.execution_time
            ),
            TaskEvent::ServerShutdown(_) => {
                "Task exiting because the server is shutting down".to_string()
            }
            TaskEvent::Error(event) => format!("Error : {:?} {}", event.code, event.message),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct TaskStarted {
    pub task_id: String,
}

#[derive(Serialize, Debug)]
pub struct TaskStdout {
    pub task_id: String,
    pub output: String,
}

#[derive(Serialize, Debug)]
pub struct TaskStderr {
    pub task_id: String,
    pub output: String,
}

#[derive(Serialize, Debug)]
pub struct TaskTimeout {
    pub task_id: String,
    pub timeout_millis: u128,
}

#[derive(Serialize, Debug)]
pub struct TaskExited {
    pub task_id: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub signal_name: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct KillSignalSent {
    pub task_id: String,
}

#[derive(Serialize, Debug)]
pub struct SignalSent {
    pub task_id: String,
    pub signal: i32,
    pub signal_name: String,
}

#[derive(Serialize, Debug)]
pub struct TaskKilled {
    pub task_id: String,
}

#[derive(Serialize, Debug)]
pub struct UnableToKillTask {
    pub task_id: String,
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct TaskTerminated {
    pub task_id: String,
    pub execution_time: u128,
}

#[derive(Serialize, Debug)]
pub struct ServerShutdown {
    pub task_id: String,
}

#[derive(Serialize, Debug)]
pub struct TaskError {
    pub task_id: String,
    pub code: ResultCode,
    pub message: String,
}

/// A Command currently running
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Task {
    /// Name of the command that this task is executing
    #[schema(value_type = String)]
    pub name: CommandName,
    /// Unique ID of the task
    #[schema(inline)]
    pub id: TaskId,
    /// Name of the user that launched this task
    pub launched_by: String,
    /// Timestamp on which this task was started
    pub start_timestamp: u64,
}

impl Task {
    /// Create a new [Task] with the given name
    pub fn new(tasks: &Tasks, name: CommandName, launched_by: String) -> Self {
        Self {
            name,
            id: TaskId::new(tasks),
            launched_by,
            start_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Check whether this task is visible to the given [User]. A normal user
    /// can only see its own tasks, while an admin can see every task.
    pub fn is_visible_to(&self, user: &User) -> bool {
        match user.role {
            UserRole::Admin => true,
            UserRole::User => self.launched_by == user.username,
        }
    }

    /// Return this task itself if it is visible to the given [User].
    /// See [is_visible_to] for more information.
    pub fn if_visible_to(&self, user: &User) -> Option<&Self> {
        if self.is_visible_to(user) {
            Some(self)
        } else {
            None
        }
    }
}

/// A unique identifier for a running Task
#[derive(Debug, Clone, Eq, Hash, PartialEq, ToSchema)]
pub struct TaskId(Uuid);

impl TaskId {
    /// Generate a new unique task identifier
    pub fn new(tasks: &Tasks) -> Self {
        loop {
            let id = Self(Uuid::new_v4());
            if !tasks.contains_key(&id) {
                return id;
            }
        }
    }

    /// Try to create a [TaskId] from the given string
    pub fn from(repr: &str) -> Option<Self> {
        Uuid::parse_str(repr).ok().map(Self)
    }
}

impl Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for TaskId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// An executable process that ownes the handle to the background async task (and therefore
/// the [Child] process object), as well as the other data required for the command to
/// run and communicate with the rest of the system.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TaskProcess {
    pub task: Task,
    pub process_command: process::Command,
    pub start_time: Option<Instant>,
    pub timeout_millis: Option<u64>,
    handle: Option<JoinHandle<()>>,
    pub output: Arc<RwLock<Vec<TaskOutputMessage>>>,
    pub output_channel: broadcast::Sender<TaskOutputMessage>,
    kill_signal_channel: Option<oneshot::Sender<()>>,
    signal_channel: Option<mpsc::Sender<UnixSignal>>,
    monitoring_channel: broadcast::Sender<TasksMonitoringMessage>,
}

impl TaskProcess {
    /// Create a new [TaskProcess] that will execute the given [Command]. The process
    /// will not be started immediately : [TaskProcess::start()] must be called manually.
    pub fn new(
        command: Command,
        task: Task,
        monitoring_channel: broadcast::Sender<TasksMonitoringMessage>,
        config: &Config,
    ) -> Self {
        let timeout_millis = command.timeout_millis;

        // Convert the Command to an executable process
        let process_command = command.into_process(config);

        // Create the struct that will manage the output of this process. One copy of the Arc will be moved into
        // the async task, while the other will be stored in the returned [TaskProcess] to be used by responders.
        let output = Default::default();

        Self {
            task,
            process_command,
            start_time: None,
            timeout_millis,
            handle: None,
            output,
            output_channel: broadcast::channel::<TaskOutputMessage>(1024).0,
            kill_signal_channel: None,
            signal_channel: None,
            monitoring_channel,
        }
    }

    /// Start a [TaskProcess] previously created with [TaskProcess::new()]. This will effectively launch the
    /// process and start an async task to manage it in the background. Communication to and from this task
    /// will pass through the [TaskProcess]'s dedicated channels.
    pub fn start(&mut self, mut shutdown: Shutdown) -> Result<(), std::io::Error> {
        // Create the kill signal channel, which will allow the system to send a request to the
        // running task to kill the child process
        let (kill_signal_send, mut kill_signal_recv) = oneshot::channel::<()>();
        self.kill_signal_channel = Some(kill_signal_send);

        // Create the generic signal channel, which will allow the system to send a request to the
        // running task to send a Unix signal to the child process
        let (signal_send, mut signal_recv) = mpsc::channel::<UnixSignal>(8);
        self.signal_channel = Some(signal_send);

        // Create a copy of the pointer to the output struct to give to the async task
        let output = self.output.clone();

        // Try to spawn the child process
        let child = self.process_command.spawn()?;

        // Clone some objects that will be moved into the async task
        let task_id = self.task.id.clone();
        let channel = self.output_channel.clone();
        let monitoring_channel = self.monitoring_channel.clone();

        // Maximum duration that the process can take to execute
        let timeout_duration = self.timeout_millis.map(Duration::from_millis);

        // Create the async task
        let handle = tokio::spawn(async move {
            // Small helper that pushes a message both on the output backlog for later use,
            // and the external channel for immediate consumption by any connected responder.
            async fn append_message(
                message: TaskOutputMessage,
                output: &Arc<RwLock<Vec<TaskOutputMessage>>>,
                channel: &broadcast::Sender<TaskOutputMessage>,
            ) {
                // Keeping the lock inside this block ensures it is held for as short as possible,
                // however we need to keep it until the message is sent on the channel to avoid a
                // possible race condition.
                let mut output = output.write().await;
                output.push(message.clone());
                channel.send(message).ok();
            }

            // Create a simple sleep task that will be used as a timeout
            let timeout_enabled = timeout_duration.is_some();
            let timeout = time::sleep(timeout_duration.unwrap_or(Duration::MAX));
            tokio::pin!(timeout);

            // Get the output of the child process as an async Stream
            let mut cmd_stream = ProcessLineStream::from(child);

            // Send the TaskStarted message that will give the clients the task id
            append_message(TaskOutputMessage::TaskStarted, &output, &channel).await;

            let mut kill_signal_received = false;
            let mut signal_channel_closed = false;
            loop {
                // Await until any relevant event is received : an output from the process, a timeout,
                // a kill signal or the server shutting down
                tokio::select! {
                    item = cmd_stream.next() => {
                        // The child sent an event :
                        match item {
                            // - some output to stdout or stderr
                            Some(Item::Stdout(data)) => append_message(TaskOutputMessage::Stdout(data), &output, &channel).await,
                            Some(Item::Stderr(data)) => append_message(TaskOutputMessage::Stderr(data), &output, &channel).await,

                            // - an exit status
                            Some(Item::Done(Ok(status))) => append_message(TaskOutputMessage::ExitCode(status.code(), status.signal()), &output, &channel).await,

                            // - another error when terminating
                            Some(Item::Done(Err(error))) => append_message(TaskOutputMessage::Error(format!("{error}")), &output, &channel).await,

                            // - (no more events available because the process terminated)
                            None => { break } // Exit the loop to terminate the async task
                        }
                    }
                    () = &mut timeout, if timeout_enabled => {
                        // Timeout expired
                        append_message(TaskOutputMessage::Timeout(timeout_duration.unwrap_or(Duration::MAX).as_millis()), &output, &channel).await;
                        break;
                    }
                    _ = &mut kill_signal_recv, if !kill_signal_received => {
                        // Received a message on the kill channel : try to kill the child process
                        kill_signal_received = true; // Required to prevent the oneshot channel to be await'ed again
                        if let Some(child) = cmd_stream.child_mut() {
                            match child.kill().await {
                                Ok(()) => append_message(TaskOutputMessage::KillSignalSent, &output, &channel).await,
                                Err(error) => append_message(TaskOutputMessage::Error(format!("{error}")), &output, &channel).await,
                            }
                        }
                    }
                    signal = signal_recv.recv(), if !signal_channel_closed => {
                        // Received a message on the signals channel
                        if let Some(signal) = signal {
                            // Find the PID of the child process
                            let Some(child) = cmd_stream.child() else {
                                eprintln!("Error : unable to send a signal to task {task_id} : cannot get child process");
                                continue;
                            };
                            let Some(pid) = child.id() else {
                                eprintln!("Error : unable to send a signal to task {task_id} : the child process doesn't have a PID");
                                continue;
                            };

                            // Send the signal using the raw libc kill function
                            let signal_result = unsafe { libc::kill(pid as i32, signal as i32) };
                            match signal_result {
                                0 => append_message(TaskOutputMessage::SignalSent(signal), &output, &channel).await,
                                ret => append_message(TaskOutputMessage::Error(format!("Unable to send a signal : libc kill returned {ret}")), &output, &channel).await,
                            }
                        } else {
                            signal_channel_closed = true;
                        }
                    }
                    _ = &mut shutdown => {
                        // The server is shutting down, cleanly exit the process
                        append_message(TaskOutputMessage::ServerShutdown, &output, &channel).await;
                        break;
                    }
                    else => { break }
                }
            }

            // Send the Terminated message to the listening clients
            append_message(TaskOutputMessage::TaskTerminated, &output, &channel).await;

            // Alert the monitoring task that this process has terminated
            monitoring_channel
                .send(TasksMonitoringMessage::Terminated(task_id.clone()))
                .ok();
        });

        // Update the internal state with the handle to the async task and the start time of the process
        self.start_time = Some(Instant::now());
        self.handle = Some(handle);

        Ok(())
    }

    /// Send the kill signal to the associated async task running the child process
    pub fn kill(&mut self) -> bool {
        if let Some(channel) = self.kill_signal_channel.take() {
            channel.send(()).is_ok()
        } else {
            false
        }
    }

    /// Send an arbitrary signal to the associated async task running the child process
    pub async fn send_signal(&mut self, signal: UnixSignal) -> bool {
        if let Some(signal_channel) = &self.signal_channel {
            signal_channel.send(signal).await.is_ok()
        } else {
            false
        }
    }
}

/// Messages that can be passed through the channel from background async tasks running
/// processes, to listening responders
#[derive(Debug, Clone)]
pub enum TaskOutputMessage {
    TaskStarted,
    Stdout(String),
    Stderr(String),
    Timeout(u128),
    KillSignalSent,
    SignalSent(UnixSignal),
    ExitCode(Option<i32>, Option<i32>),
    Error(String),
    ServerShutdown,
    TaskTerminated,
}

impl TaskOutputMessage {
    /// Helper function that consumes this message and converts it to a [TaskEvent] (if relevant)
    pub fn into_task_event(self, task_id: &TaskId, start_time: &Instant) -> Option<TaskEvent> {
        match self {
            TaskOutputMessage::TaskStarted => Some(TaskEvent::TaskStarted(TaskStarted {
                task_id: task_id.to_string(),
            })),
            TaskOutputMessage::Stdout(output) => Some(TaskEvent::Stdout(TaskStdout {
                task_id: task_id.to_string(),
                output,
            })),
            TaskOutputMessage::Stderr(output) => Some(TaskEvent::Stdout(TaskStdout {
                task_id: task_id.to_string(),
                output,
            })),
            TaskOutputMessage::Timeout(timeout_millis) => {
                Some(TaskEvent::TaskTimeout(TaskTimeout {
                    task_id: task_id.to_string(),
                    timeout_millis,
                }))
            }
            TaskOutputMessage::KillSignalSent => Some(TaskEvent::KillSignalSent(KillSignalSent {
                task_id: task_id.to_string(),
            })),
            TaskOutputMessage::SignalSent(signal) => Some(TaskEvent::SignalSent(SignalSent {
                task_id: task_id.to_string(),
                signal: signal as i32,
                signal_name: signal.to_string(),
            })),
            TaskOutputMessage::ExitCode(exit_code, signal) => {
                Some(TaskEvent::TaskExited(TaskExited {
                    task_id: task_id.to_string(),
                    exit_code,
                    signal,
                    signal_name: signal
                        .and_then(UnixSignal::from_repr)
                        .map(|s| s.to_string()),
                }))
            }
            TaskOutputMessage::Error(error) => Some(TaskEvent::Error(TaskError {
                task_id: task_id.to_string(),
                code: ResultCode::InternalServerError,
                message: error,
            })),
            TaskOutputMessage::ServerShutdown => Some(TaskEvent::ServerShutdown(ServerShutdown {
                task_id: task_id.to_string(),
            })),
            TaskOutputMessage::TaskTerminated => Some(TaskEvent::TaskTerminated(TaskTerminated {
                task_id: task_id.to_string(),
                execution_time: start_time.elapsed().as_millis(),
            })),
        }
    }
}

/// List of existing Unix signals with name and associated code, according
/// to `man 7 signal`. This is used to give the human-readable signal name
/// to clients along the signal code.
#[derive(Debug, Copy, Clone, FromRepr, Display)]
#[repr(i32)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum UnixSignal {
    Sighup = 1,
    Sigint = 2,
    Sigquit = 3,
    Sigill = 4,
    Sigtrap = 5,
    Sigabrt = 6,
    Sigbus = 7,
    Sigfpe = 8,
    Sigkill = 9,
    Sigusr1 = 10,
    Sigsegv = 11,
    Sigusr2 = 12,
    Sigpipe = 13,
    Sigalrm = 14,
    Sigterm = 15,
    Sigstkflt = 16,
    Sigchld = 17,
    Sigcont = 18,
    Sigstop = 19,
    Sigtstp = 20,
    Sigttin = 21,
    Sigttou = 22,
    Sigurg = 23,
    Sigxcpu = 24,
    Sigxfsz = 25,
    Sigvtalrm = 26,
    Sigprof = 27,
    Sigwinch = 28,
    Sigio = 29,
    Sigpwr = 30,
    Sigsys = 31,
}

pub type TasksList = HashMap<TaskId, Task>;

/// Container for the [Task]s currently running
#[derive(Debug)]
pub struct Tasks {
    tasks: TasksList,
    tasks_ids_by_name: HashMap<CommandName, Vec<TaskId>>,
    tasks_processes: HashMap<TaskId, TaskProcess>,
    tasks_channel: broadcast::Sender<TasksList>,
    monitoring_channel: broadcast::Sender<TasksMonitoringMessage>,
}

/// A message passed through the monitoring channel from an async task
/// to the main monitoring task
#[derive(Debug, Clone)]
pub enum TasksMonitoringMessage {
    Terminated(TaskId),
}

impl Tasks {
    /// Create a new [Tasks] container
    pub fn new(tasks_channel: broadcast::Sender<TasksList>) -> Self {
        Self {
            tasks: HashMap::new(),
            tasks_ids_by_name: HashMap::new(),
            tasks_processes: HashMap::new(),
            tasks_channel,
            monitoring_channel: broadcast::channel::<TasksMonitoringMessage>(16).0,
        }
    }

    /// Start a background monitoring task that receives and handles events on the [Tasks]'s monitoring
    /// channel, and updates that task
    pub async fn start_monitoring_task(tasks: Weak<RwLock<Self>>) {
        // Subscribe to the monitoring channel of this [Tasks] struct
        let mut monitoring_channel = {
            if let Some(tasks) = tasks.upgrade() {
                let tasks = tasks.read().await;
                tasks.monitoring_channel.subscribe()
            } else {
                return;
            }
        };

        // Spawn the async task
        tokio::spawn(async move {
            loop {
                // Wait for an message on the monitoring channel
                let recv_message = monitoring_channel.recv().await;
                match recv_message {
                    Ok(message) => {
                        if let Some(tasks) = tasks.upgrade() {
                            // Handle the message that was received
                            let mut tasks = tasks.write().await;
                            match message {
                                TasksMonitoringMessage::Terminated(task_id) => {
                                    // The task terminated, remove it from the list. If necessary, this could be
                                    // changed so that terminated tasks are kept in memory for some time to give
                                    // users the ability to asynchronously check their output and exit status.
                                    tasks.remove(&task_id);
                                }
                            }
                        } else {
                            // The pointer to the Tasks struct has been invalidated, which means the underlying
                            // Tasks object was dropped. There is nothing else we can do, stop monitoring.
                            break;
                        }
                    }
                    // The monitoring channel was closed, which means the Tasks struct was dropped. Exit.
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("Warning : monitoring task missed {n} messages");
                    }
                }
            }
        });
    }

    /// Get a reference to the internal list of currently running tasks
    pub fn list(&self) -> &TasksList {
        &self.tasks
    }

    /// Create a new async task based on the given [Command] and return a reference to the new [TaskProcess].
    /// The process will not be started yet.
    pub fn create(
        &mut self,
        command: Command,
        launched_by: String,
        config: &Config,
    ) -> &mut TaskProcess {
        // Create the [Task] metadata struct and save it in the local hashmaps
        let task = Task::new(self, command.name.clone(), launched_by);
        let task_id = task.id.clone();
        self.tasks.insert(task.id.clone(), task.clone());
        self.tasks_ids_by_name
            .entry(command.name.clone())
            .or_insert_with(Vec::new)
            .push(task.id.clone());

        // Create the [TaskProcess] handler on the process and give it a new Sender
        // on the monitoring channel to send its updates to
        let task_process = TaskProcess::new(
            command,
            task.clone(),
            self.monitoring_channel.clone(),
            config,
        );
        self.tasks_processes.insert(task_id.clone(), task_process);

        // We have a new task running, send the update to everyone listening
        self.tasks_channel.send(self.tasks.clone()).ok();

        // Return a mutable reference to the [TaskProcess] that can be used to immediately start it
        self.tasks_processes.get_mut(&task_id).unwrap()
    }

    /// Get a reference to the [TaskProcess] related to the given id, if any
    pub fn get_process(&self, task_id: &TaskId) -> Option<&TaskProcess> {
        self.tasks_processes.get(task_id)
    }

    /// Check whether a task with the given name is running
    pub fn is_running(&self, name: &CommandName) -> bool {
        self.tasks_ids_by_name.get(name).is_some()
    }

    /// Remove the given task from the container
    pub fn remove(&mut self, id: &TaskId) -> Option<Task> {
        let result = self.remove_internal(id);
        self.tasks_channel.send(self.tasks.clone()).ok();
        result
    }

    /// Remove the given task from the container without sending updates
    fn remove_internal(&mut self, id: &TaskId) -> Option<Task> {
        let deleted_task = self.tasks.remove(id);
        if let Some(deleted_task) = &deleted_task {
            if let Some(ids) = self.tasks_ids_by_name.get_mut(&deleted_task.name) {
                ids.retain(|id| id != &deleted_task.id);
                if ids.is_empty() {
                    self.tasks_ids_by_name.remove(&deleted_task.name);
                }
            }
        }
        self.tasks_processes.remove(id);
        deleted_task
    }

    /// Send the kill signal to the given task as the given [User]
    pub fn kill(&mut self, id: &TaskId, user: &User) -> Option<bool> {
        if self
            .tasks
            .get(id)
            .is_some_and(|task| task.is_visible_to(user))
        {
            if let Some(task_process) = self.tasks_processes.get_mut(id) {
                return Some(task_process.kill());
            }
        }
        None
    }

    /// Send a signal to the given task as the given [User]
    pub async fn send_signal(
        &mut self,
        id: &TaskId,
        signal: UnixSignal,
        user: &User,
    ) -> Option<bool> {
        if self
            .tasks
            .get(id)
            .is_some_and(|task| task.is_visible_to(user))
        {
            if let Some(task_process) = self.tasks_processes.get_mut(id) {
                return Some(task_process.send_signal(signal).await);
            }
        }
        None
    }

    /// Return an iterator over the list of tasks visible to this user
    pub fn visible_to<'a>(&'a self, user: &'a User) -> impl Iterator<Item = &Task> + 'a {
        self.tasks
            .iter()
            .filter_map(|(_, task)| task.if_visible_to(user))
    }
}

impl Deref for Tasks {
    type Target = HashMap<TaskId, Task>;

    fn deref(&self) -> &Self::Target {
        &self.tasks
    }
}
