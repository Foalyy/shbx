use crate::Error;
use base64::Engine;
use rand::RngCore;
use rocket::serde::Deserialize;
use std::fs::File;
use std::io::{self, Write};
use std::{fs, path::PathBuf};

/// Name of the main config file in the app's folder
pub const FILENAME: &str = "shbx.config";

/// The main config for the app
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct Config {
    /// IP address to serve on. Set to "0.0.0.0" to serve on all interfaces.
    /// Default : 127.0.0.1 (only accessible locally)
    #[serde(default = "config_default_address")]
    pub address: String,

    /// Port to serve on.
    /// Default : 8000
    #[serde(default = "config_default_port")]
    pub port: u16,

    /// Path to the SQLite database file used by the app to store ShellBox's data. It will
    /// be automatically created during the first launch, so write access to the containing
    /// folder is required.
    /// Default : "shbx.sqlite" (in the app's folder)
    #[serde(default = "config_default_database_path")]
    pub database_path: PathBuf,

    /// Path to the commands definition file.
    /// Default : "commands.config" (in the app's folder)
    #[serde(default = "config_default_commands_path")]
    pub commands_path: PathBuf,

    /// Path to the default working directory to execute the commands in.
    /// Default : (the system's temporary directory, such as /tmp on Unix)
    #[serde(default = "PathBuf::new")]
    pub working_dir: PathBuf,

    /// Default timeout after which a command is killed, in milliseconds.
    /// Default : 10000ms
    #[serde(default = "config_default_timeout_millis")]
    pub timeout_millis: u64,
}

impl Config {
    /// Read the main config file and deserialize it into a Config struct
    pub fn read() -> Result<Self, Error> {
        // Read the config file and parse it as a Config struct
        let path = PathBuf::from(FILENAME);
        let file_content =
            fs::read_to_string(&path).map_err(|e| Error::FileError(e, path.clone()))?;
        let mut config: Config = toml::from_str(file_content.as_str())?;

        // Check this config
        if !config.commands_path.is_file() {
            return Err(Error::CommandsConfigFileNotFound(config.commands_path));
        }
        if config.working_dir == PathBuf::new() {
            config.working_dir = std::env::temp_dir();
        } else if config.working_dir.is_relative() {
            let mut working_dir = std::env::temp_dir();
            working_dir.push(config.working_dir);
            config.working_dir = working_dir;
        }
        config.working_dir = config
            .working_dir
            .canonicalize()
            .map_err(|e| Error::InvalidConfigWorkingDir(config.working_dir.clone(), e))?;
        if !config.working_dir.is_dir() {
            return Err(Error::ConfigWorkingDirNotADir(config.working_dir));
        }

        Ok(config)
    }

    /// Try to read and parse the config file
    /// In case of error, print it to stderr and exit with a status code of -1
    pub fn read_or_exit() -> Self {
        // Read the config file and parse it into a Config struct
        Self::read().unwrap_or_else(|e| match e {
            Error::FileError(error, path) => {
                eprintln!(
                    "Error, unable to open the config file \"{}\" : {}",
                    path.display(),
                    error
                );
                std::process::exit(-1);
            }
            Error::TomlParserError(error) => {
                eprintln!("Error, unable to parse the config file \"{FILENAME}\" : {error}");
                std::process::exit(-1);
            }
            error => {
                eprintln!("Error, invalid setting in the config file \"{FILENAME}\" : {error}");
                std::process::exit(-1)
            }
        })
    }
}

// Default values for config keys

fn config_default_address() -> String {
    "127.0.0.1".to_string()
}

fn config_default_port() -> u16 {
    8000
}

fn config_default_database_path() -> PathBuf {
    PathBuf::from("shbx.sqlite")
}

fn config_default_commands_path() -> PathBuf {
    PathBuf::from("commands.config")
}

fn config_default_timeout_millis() -> u64 {
    10000
}

/// Try to open the .secret file in the app's directory and return
/// the secret key inside. If this file doesn't exist, try to generate
/// a new one. In case of an error, print the error on stderr and exit.
pub fn get_secret_key_or_exit() -> String {
    let path = PathBuf::from(".secret");
    match fs::read_to_string(&path) {
        Ok(secret) => secret.trim().to_string(),

        // The secret file doesn't exist, try to generate one
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            print!("Secret file not found, generating a new one... ");
            let mut rand_buffer = [0; 32];
            rand::thread_rng().fill_bytes(&mut rand_buffer);
            let secret = base64::engine::general_purpose::STANDARD.encode(rand_buffer);
            let mut file = File::create(&path).unwrap_or_else(|error| {
                eprintln!("\nError : unable to create the .secret file : {error}");
                std::process::exit(-1);
            });
            writeln!(&mut file, "{secret}").unwrap_or_else(|error| {
                eprintln!("\nError : unable to write to the .secret file : {error}");
                std::process::exit(-1);
            });
            println!(" done");
            secret
        }

        // The secret file can't be read for some other reason
        Err(error) => {
            eprintln!("Error : unable to read the .secret file : {error}");
            std::process::exit(-1);
        }
    }
}
