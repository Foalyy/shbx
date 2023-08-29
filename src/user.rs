use crate::{
    api::{ApiKey, SessionStore},
    command::{CommandName, Commands},
    db::{self, DB},
    Error,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use rand::seq::SliceRandom;
use rocket::{
    http::Status,
    request::{self, FromRequest},
    Request, State,
};
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use strum::{Display, EnumString};
use tokio::sync::RwLock;
use utoipa::ToSchema;

/// A user that can log in the system
#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct User {
    pub username: String,
    pub role: UserRole,
    #[serde(skip)]
    pub hashed_password: Option<String>,
    #[schema(inline)]
    pub api_key: ApiKey,
    #[serde(skip)]
    pub session_key: Option<ApiKey>,
    #[schema(value_type = Vec<String>)]
    pub commands: Vec<CommandName>,
}

impl User {
    pub fn update_with(&mut self, update: &UpdatedUser) {
        if let Some(role) = update.role {
            self.role = role;
        }
        if let Some(commands) = update.commands.clone() {
            self.commands = commands;
        }
    }
}

/// Make [User] a request guard so that the current user can be directly recovered by the routes
/// based on the 'X-API-Key' header in the request
#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = UserRequestGuardError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Try to read the key from the headers of the request
        let key = match request.headers().get_one("X-API-Key") {
            Some(key) => key,
            None => {
                // Header 'X-API-Key' not found : return Access Unauthorized
                return request::Outcome::Failure((
                    Status::Unauthorized,
                    Self::Error::AccessUnauthorized,
                ));
            }
        };
        let api_key = key.into();

        // Get access to the session store
        let session_store = match request.guard::<&State<SessionStore>>().await {
            request::Outcome::Success(session_store) => session_store,
            _ => {
                // Cannot access the session store. Something went wrong, this shouldn't happen.
                return request::Outcome::Failure((
                    Status::InternalServerError,
                    Self::Error::InternalServerError(
                        "Error : unable to access the session store".to_string(),
                    ),
                ));
            }
        };

        // Clean up old sessions from the session store
        session_store.cleanup().await;

        // Try to find a user with the given session key in the session store
        if let Some(user) = session_store.get_and_touch(&api_key).await {
            // User found : return it
            return request::Outcome::Success(user);
        }

        // Session key not found in the store

        // Get access to the database
        let mut db_conn = match request.guard::<Connection<DB>>().await {
            request::Outcome::Success(db_conn) => db_conn,
            _ => {
                // Cannot access the database. Something went wrong, this shouldn't happen.
                return request::Outcome::Failure((
                    Status::InternalServerError,
                    Self::Error::InternalServerError(
                        "Error : unable to access the database".to_string(),
                    ),
                ));
            }
        };

        // Get the list of commands
        let commands = match request.guard::<&State<RwLock<Commands>>>().await {
            request::Outcome::Success(commands) => commands,
            _ => {
                // Cannot access the list of commands. Something went wrong, this shouldn't happen.
                return request::Outcome::Failure((
                    Status::InternalServerError,
                    Self::Error::InternalServerError(
                        "Error : unable to access the list of commands".to_string(),
                    ),
                ));
            }
        };

        // Try to find a matching permanent API key in the database
        let user = {
            let commands = commands.read().await;
            db::find_user_from_api_key(&mut db_conn, &commands, &api_key).await
        };
        match user {
            // User found in the database with this permanent API key, add it to the store and return it
            Ok(Some(user)) => {
                session_store
                    .new_session_with_key(user.clone(), api_key.clone())
                    .await;
                request::Outcome::Success(user)
            }

            // User not found in the database : key is invalid, return Access Forbidden
            Ok(None) => {
                request::Outcome::Failure((Status::Forbidden, Self::Error::AccessForbidden))
            }

            // An error happened while trying to find the user in the database
            Err(error) => request::Outcome::Failure((
                Status::InternalServerError,
                Self::Error::InternalServerError(format!(
                    "Error : unable to read from the database : {error}"
                )),
            )),
        }
    }
}

/// A custom User type that can only represent an admin, to use as a request guard.
/// An [AdminUser] can only be created through its [FromRequest] implementation, which
/// guarantees that it is not possible to create an [AdminUser] with a a role different
/// than [UserRole::Admin].
pub struct AdminUser {
    user: User,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = UserRequestGuardError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Delegate most of the work to the FromRequest implementation of User
        match User::from_request(request).await {
            // Found a valid admin user : return it
            request::Outcome::Success(user) if matches!(user.role, UserRole::Admin) => {
                request::Outcome::Success(AdminUser { user })
            }

            // Found a valid user that is not admin : convert the Success to a Failure
            // with AccessForbidden
            request::Outcome::Success(_) => {
                request::Outcome::Failure((Status::Forbidden, Self::Error::AccessForbidden))
            }

            // Any failure : return it
            request::Outcome::Failure(error) => request::Outcome::Failure(error),

            // Anything else : forward
            _ => request::Outcome::Forward(()),
        }
    }
}

impl Deref for AdminUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

/// A custom error type for the different kinds of User request guards
#[derive(Error, Debug)]
pub enum UserRequestGuardError {
    /// Authentication not provided
    #[error("access unauthorized")]
    AccessUnauthorized,

    /// Provided authentication is invalid
    #[error("access forbidden")]
    AccessForbidden,

    /// Something went wrong during the process
    #[error("internal server error : {0}")]
    InternalServerError(String),
}

/// Information about a new user to create, deserialized from Json data
#[derive(Debug, Deserialize, Clone, ToSchema)]
pub struct NewUser {
    pub username: String,
    pub role: UserRole,
    #[schema(value_type = String)]
    pub password: PlaintextPassword,
    #[schema(value_type = Vec<String>)]
    pub commands: Vec<CommandName>,
}

/// Information that can be updated about a user, deserialized from Json data.
/// All fields are optional.
#[derive(Debug, Deserialize, Clone, ToSchema)]
pub struct UpdatedUser {
    pub role: Option<UserRole>,
    #[schema(value_type = Option<String>)]
    pub password: Option<PlaintextPassword>,
    #[schema(value_type = Option<Vec<String>>)]
    pub commands: Option<Vec<CommandName>>,
}

/// Available roles for users
#[derive(Display, Serialize, Deserialize, EnumString, PartialEq, Clone, Copy, Debug, ToSchema)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    User,
}

/// A plaintext password
#[derive(Debug, Deserialize, Clone)]
pub struct PlaintextPassword(pub String);

impl PlaintextPassword {
    pub const CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /// Generate a random password of the given length
    pub fn random(length: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sample = Self::CHARS
            .as_bytes()
            .choose_multiple(&mut rng, length)
            .cloned()
            .collect::<Vec<u8>>();
        let password_str =
            String::from_utf8(sample).expect("Error, unable to generate a random password");
        Self(password_str)
    }

    /// Return the hash of this password with a random salt
    pub fn hash_with_random_salt(&self) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(self.0.as_bytes(), &salt)
            .expect("Unable to hash a password")
            .to_string()
    }

    /// Check whether this password matches the given hash
    pub fn verify(&self, hash: &String) -> bool {
        match PasswordHash::new(hash) {
            Ok(parsed_hash) => Argon2::default()
                .verify_password(self.0.as_bytes(), &parsed_hash)
                .is_ok(),
            Err(_) => {
                eprintln!(
                    "Warning : cannot parse the given string as a password hash : \'{hash}\'"
                );
                false
            }
        }
    }
}

impl From<&str> for PlaintextPassword {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Display for PlaintextPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
