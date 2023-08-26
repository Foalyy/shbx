use crate::{config::Config, user::User, Error};
use rocket::tokio::fs;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Deref, path::PathBuf, time::SystemTime};

pub type CommandName = String;

/// A command as written in the config file
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CommandConfig {
    pub name: CommandName,
    pub label: Option<String>,
    pub path: PathBuf,
}

/// A command that ShellBox can execute
#[derive(Clone, Serialize, Debug)]
pub struct Command {
    pub name: String,
    pub label: String,
    pub path: PathBuf,
}

impl Command {
    /// Try to build a valid [Command] from the given [CommandConfig]
    pub fn from_config(command_config: &CommandConfig) -> Result<Self, CommandConfigError> {
        let name = command_config.name.clone();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(CommandConfigError::InvalidName(name));
        }
        let label = command_config.label.clone().unwrap_or_else(|| name.clone());
        let path = command_config.path.canonicalize().map_err(|io_error| {
            CommandConfigError::InvalidPath(command_config.path.clone(), io_error)
        })?;
        if !path.exists() {
            return Err(CommandConfigError::PathDoesNotExist(path));
        }
        Ok(Self { name, label, path })
    }
}

/// Errors that can happen when trying to build a [Command] object from a [CommandConfig]
#[derive(thiserror::Error, Debug)]
pub enum CommandConfigError {
    #[error("invalid command name \"{0}\", only letters, digits and underscores are allowed")]
    InvalidName(String),
    #[error("invalid path \"{0}\" : {1}")]
    InvalidPath(PathBuf, std::io::Error),
    #[error("path \"{0}\" does not exist")]
    PathDoesNotExist(PathBuf),
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
                    "Read {} commands from {}",
                    commands.len(),
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
                let command = Command::from_config(command_config)?;
                let previous_entry = commands.insert(command.name.clone(), command);
                if let Some(previous_entry) = previous_entry {
                    return Err(Error::DuplicateCommandName(previous_entry.name));
                }
            }

            // Update self
            self.commands = commands;
            self.modified_time = file_modified_time;
            println!("Commands config file updated");
            Ok(true)
        } else {
            Ok(false)
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
                if user.commands.contains(name) {
                    Some(command.clone())
                } else {
                    None
                }
            })
            .collect()
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
