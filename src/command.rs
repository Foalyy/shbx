use crate::{
    config::Config,
    user::{User, UserRole},
    utils, Error,
};
use is_executable::IsExecutable;
use rocket::tokio::fs;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Deref, path::PathBuf, process::Stdio, time::SystemTime};
use tokio::process;

pub type CommandName = String;

/// A command as written in the config file
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CommandConfig {
    pub name: CommandName,
    pub label: Option<String>,
    pub shell: Option<bool>,
    pub timeout_millis: Option<u64>,
    pub exec: String,
    pub working_dir: Option<PathBuf>,
}

/// A command that ShellBox can execute
#[derive(Clone, Serialize, Debug)]
pub struct Command {
    pub name: String,
    pub label: String,
    pub shell: bool,
    #[serde(skip)]
    pub timeout_millis: u64,
    pub exec: String,
    #[serde(skip)]
    pub cmd: CommandExec,
    #[serde(skip)]
    pub working_dir: PathBuf,
}

/// Path and arguments of an executable command
#[derive(Clone, Debug)]
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

        Ok(Self {
            name,
            label,
            shell: command_config.shell.unwrap_or(false),
            timeout_millis: command_config
                .timeout_millis
                .unwrap_or(config.timeout_millis),
            exec,
            cmd: CommandExec {
                path: exec_path_cmd,
                args: exec_path_args,
            },
            working_dir,
        })
    }

    /// Consume this [Command] and convert it into a [process::Command] ready to be executed.
    pub fn into_process(self) -> process::Command {
        let mut cmd = if self.shell {
            let mut cmd = process::Command::new("sh");
            cmd.arg("-c");
            cmd.arg(self.exec);
            cmd
        } else {
            let mut cmd = process::Command::new(self.cmd.path);
            cmd.args(self.cmd.args);
            cmd
        };
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
    commands: HashMap<CommandName, Command>,
    modified_time: SystemTime,
}

impl Commands {
    /// Create a new commands container
    pub async fn read_or_exit(config: &Config) -> Self {
        let mut commands = Self {
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
                    "Error : unable to read the commands config file \"{}\" : {error}",
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
            let mut commands = HashMap::new();
            for command_config in &commands_config.commands {
                let command = Command::from_config(command_config, config)?;
                let previous_entry = commands.insert(command.name.clone(), command);
                if let Some(previous_entry) = previous_entry {
                    return Err(Error::DuplicateCommandName(previous_entry.name));
                }
            }

            // Update self
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
        self.iter()
            .filter_map(|(name, command)| {
                if user.role == UserRole::Admin || user.commands.contains(name) {
                    Some(command.clone())
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
#[derive(Serialize, Debug)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl From<std::process::Output> for CommandResult {
    fn from(value: std::process::Output) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&value.stdout).to_string(),
            stderr: String::from_utf8_lossy(&value.stderr).to_string(),
            exit_code: value.status.code(),
        }
    }
}

/// Item in a result stream of a command that was executed by a user
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamCommandResult {
    Stdout(String),
    Stderr(String),
    ExitCode(Option<i32>),
    Error(String),
}
