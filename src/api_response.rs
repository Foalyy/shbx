use crate::{
    api::ApiKey,
    command::{Command, CommandName, CommandResult, Task, TaskId},
    user::User,
};

use rocket::serde::json::Json;
use serde::Serialize;
use serde_repr::Serialize_repr;
use utoipa::ToSchema;

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

    #[response(status = 500)]
    CommandFailedWithOutput(Json<MessageResponseWithOutput>),

    #[response(status = 409)]
    CommandAlreadyRunning(Json<MessageResponse>),

    #[response(status = 200)]
    CommandLaunched(Json<MessageResponseWithTaskId>),

    #[response(status = 408)]
    CommandTimeout(Json<MessageResponse>),

    #[response(status = 200)]
    CommandResult(Json<CommandResult>),

    #[response(status = 408)]
    CommandTimeoutWithOutput(Json<MessageResponseWithOutput>),

    #[response(status = 503)]
    ServerShutdownWithOutput(Json<MessageResponseWithOutput>),

    #[response(status = 200)]
    Tasks(Json<Vec<Task>>),

    #[response(status = 404)]
    InvalidTaskId(Json<MessageResponse>),

    #[response(status = 200)]
    TaskKilled(Json<MessageResponse>),

    #[response(status = 500)]
    UnableToKillTask(Json<MessageResponse>),

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
        Self::BadRequest(Json(Self::bad_request_response()))
    }

    /// Return the inner [MessageResponse] for a BadRequest response
    pub fn bad_request_response() -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::BadRequest,
            message: "Bad request".to_string(),
        }
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
        Self::NotFound(Json(Self::not_found_response()))
    }

    /// Return the inner [MessageResponse] for a NotFound response
    pub fn not_found_response() -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: "Not found".to_string(),
        }
    }

    /// Return an UnprocessableEntity response
    pub fn unprocessable_entity() -> Self {
        Self::UnprocessableEntity(Json(MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: "Invalid request data".to_string(),
        }))
    }

    /// Return an UnprocessableEntity response with a custom message
    pub fn unprocessable_entity_with_message(message: &str) -> Self {
        Self::UnprocessableEntity(Json(Self::unprocessable_entity_with_message_response(
            message,
        )))
    }

    /// Return the inner [MessageResponse] for an UnprocessableEntity response with a custom message
    pub fn unprocessable_entity_with_message_response(message: &str) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: format!("Invalid request data : {message}"),
        }
    }

    /// Return an InternalServerError response
    pub fn internal_server_error() -> Self {
        Self::InternalServerError(Json(Self::internal_server_error_response()))
    }

    /// Return the inner [MessageResponse] for a InternalServerError response
    pub fn internal_server_error_response() -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::InternalServerError,
            message: "Internal server error".to_string(),
        }
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

    /// Return a CommandFailedWithOutput response
    pub fn command_failed_with_output(
        stdout: String,
        stderr: String,
        error: String,
        execution_time: u128,
    ) -> Self {
        Self::CommandFailedWithOutput(Json(Self::command_failed_with_output_response(
            stdout,
            stderr,
            error,
            execution_time,
        )))
    }

    /// Return the inner [MessageResponseWithOutput] for a CommandFailedWithOutput response
    pub fn command_failed_with_output_response(
        stdout: String,
        stderr: String,
        error: String,
        execution_time: u128,
    ) -> MessageResponseWithOutput {
        MessageResponseWithOutput {
            result: ResultStatus::Error,
            code: ResultCode::InternalProcessError,
            message: format!("Command failed : {error}"),
            stdout,
            stderr,
            execution_time,
        }
    }

    /// Return a CommandAlreadyRunning response
    pub fn command_already_running() -> Self {
        Self::CommandAlreadyRunning(Json(Self::command_already_running_response()))
    }

    /// Return the inner [MessageResponse] for a CommandAlreadyRunning response
    pub fn command_already_running_response() -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Conflict,
            message: "Command already running".to_string(),
        }
    }

    /// Return a CommandLaunched response
    pub fn command_launched(task_id: TaskId) -> Self {
        Self::CommandLaunched(Json(Self::command_launched_response(task_id)))
    }

    /// Return the inner [MessageResponse] for a CommandLaunched response
    pub fn command_launched_response(task_id: TaskId) -> MessageResponseWithTaskId {
        MessageResponseWithTaskId {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("Command launched with id {task_id}"),
            task_id,
        }
    }

    /// Return a CommandTimeout response
    pub fn command_timeout(timeout_millis: u128, execution_time: u128) -> Self {
        Self::CommandTimeout(Json(Self::command_timeout_response(
            timeout_millis,
            execution_time,
        )))
    }

    /// Return the inner [MessageResponse] for a CommandTimeout response
    pub fn command_timeout_response(timeout_millis: u128, execution_time: u128) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::RequestTimeout,
            message: format!(
                "Command timeout after reaching the maximum execution time of {}ms (actual execution time: {}ms)",
                timeout_millis,
                execution_time
            ),
        }
    }

    /// Return a CommandTimeoutWithOutput response
    pub fn command_timeout_with_output(
        stdout: String,
        stderr: String,
        timeout_millis: u128,
        execution_time: u128,
    ) -> Self {
        Self::CommandTimeoutWithOutput(Json(Self::command_timeout_with_output_response(
            stdout,
            stderr,
            timeout_millis,
            execution_time,
        )))
    }

    /// Return the inner [MessageResponseWithOutput] for a CommandTimeoutWithOutput response
    pub fn command_timeout_with_output_response(
        stdout: String,
        stderr: String,
        timeout_millis: u128,
        execution_time: u128,
    ) -> MessageResponseWithOutput {
        MessageResponseWithOutput {
            result: ResultStatus::Error,
            code: ResultCode::RequestTimeout,
            message: format!(
                "Command timeout after reaching the maximum execution time of {}ms (actual execution time: {}ms)",
                timeout_millis,
                execution_time
            ),
            stdout,
            stderr,
            execution_time,
        }
    }

    /// Return a ServerShutdownWithOutput response
    pub fn server_shutdown_with_output(
        stdout: String,
        stderr: String,
        execution_time: u128,
    ) -> Self {
        Self::ServerShutdownWithOutput(Json(Self::server_shutdown_with_output_response(
            stdout,
            stderr,
            execution_time,
        )))
    }

    /// Return the inner [MessageResponseWithOutput] for a ServerShutdownWithOutput response
    pub fn server_shutdown_with_output_response(
        stdout: String,
        stderr: String,
        execution_time: u128,
    ) -> MessageResponseWithOutput {
        MessageResponseWithOutput {
            result: ResultStatus::Error,
            code: ResultCode::ServiceUnavailable,
            message: "Server is shutting down".to_string(),
            stdout,
            stderr,
            execution_time,
        }
    }

    /// Return a InvalidTaskId response
    pub fn invalid_task_id(repr: String) -> Self {
        Self::InvalidTaskId(Json(Self::invalid_task_id_response(repr)))
    }

    /// Return the inner [MessageResponse] for a InvalidTaskId response
    pub fn invalid_task_id_response(repr: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: format!("Invalid task id : \"{repr}\""),
        }
    }

    /// Return a TaskKilled response
    pub fn task_killed(task_id: &TaskId) -> Self {
        Self::TaskKilled(Json(Self::task_killed_response(task_id)))
    }

    /// Return the inner [MessageResponse] for a TaskKilled response
    pub fn task_killed_response(task_id: &TaskId) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("Kill signal sent to task \"{task_id}\""),
        }
    }

    /// Return a UnableToKillTask response
    pub fn unable_to_kill_task(task_id: &TaskId) -> Self {
        Self::UnableToKillTask(Json(Self::unable_to_kill_task_response(task_id)))
    }

    /// Return the inner [MessageResponse] for a UnableToKillTask response
    pub fn unable_to_kill_task_response(task_id: &TaskId) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::InternalServerError,
            message: format!("Unable to send kill signal to task \"{task_id}\""),
        }
    }

    /// Return a UserCreated response
    pub fn user_created(username: String) -> Self {
        Self::UserCreated(Json(Self::user_created_response(username)))
    }

    /// Return the inner [MessageResponse] for a UserCreated response
    pub fn user_created_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' created successfully"),
        }
    }

    /// Return a UserAlreadyExists response
    pub fn user_already_exists(username: String) -> Self {
        Self::UserAlreadyExists(Json(Self::user_already_exists_response(username)))
    }

    /// Return the inner [MessageResponse] for a UserAlreadyExists response
    pub fn user_already_exists_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::Conflict,
            message: format!("User '{username}' already exists"),
        }
    }

    /// Return a UserUpdated response
    pub fn user_updated(username: String) -> Self {
        Self::UserUpdated(Json(Self::user_updated_response(username)))
    }

    /// Return the inner [MessageResponse] for a UserUpdated response
    pub fn user_updated_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' updated successfully"),
        }
    }

    /// Return a UserApiKeyRevoked response
    pub fn user_api_key_revoked(username: String) -> Self {
        Self::UserApiKeyRevoked(Json(Self::user_api_key_revoked_response(username)))
    }

    /// Return the inner [MessageResponse] for a UserApiKeyRevoked response
    pub fn user_api_key_revoked_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("API key of user '{username}' revoked and regenerated successfully"),
        }
    }

    /// Return a UserDeleted response
    pub fn user_deleted(username: String) -> Self {
        Self::UserDeleted(Json(Self::user_deleted_response(username)))
    }

    /// Return the inner [MessageResponse] for a UserDeleted response
    pub fn user_deleted_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Success,
            code: ResultCode::Ok,
            message: format!("User '{username}' deleted successfully"),
        }
    }

    /// Return a InvalidUsername response
    pub fn invalid_username(username: String) -> Self {
        Self::InvalidUsername(Json(Self::invalid_username_response(username)))
    }

    /// Return the inner [MessageResponse] for a InvalidUsername response
    pub fn invalid_username_response(username: String) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::NotFound,
            message: format!("Invalid username : '{username}' not found"),
        }
    }

    /// Return an InvalidUserCommand response
    pub fn invalid_user_command(command_name: CommandName) -> Self {
        Self::InvalidUserCommand(Json(Self::invalid_user_command_response(command_name)))
    }

    /// Return the inner [MessageResponse] for a InvalidUserCommand response
    pub fn invalid_user_command_response(command_name: CommandName) -> MessageResponse {
        MessageResponse {
            result: ResultStatus::Error,
            code: ResultCode::UnprocessableEntity,
            message: format!("Invalid request data : invalid command name : '{command_name}'"),
        }
    }
}

/// A standardized message response returned by some of the API endpoints,
/// especially in case of errors
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponse {
    /// Result of this request, either 'success' or 'error'
    result: ResultStatus,
    /// HTTP response code returned by this request
    code: ResultCode,
    /// Human-readable details about this response
    message: String,
}

/// A standardized message response returned by some of the API endpoints,
/// especially in case of errors, combined with a task id
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponseWithTaskId {
    /// Result of this request, either 'success' or 'error'
    result: ResultStatus,
    /// HTTP response code returned by this request
    code: ResultCode,
    /// Human-readable details about this response
    message: String,
    /// Task id
    task_id: TaskId,
}

/// A standardized message response returned by some of the API endpoints,
/// especially in case of errors, combined with the stdout/stderr output
/// of a command (which may be incomplete)
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponseWithOutput {
    /// Result of this request, either 'success' or 'error'
    result: ResultStatus,
    /// HTTP response code returned by this request
    code: ResultCode,
    /// Human-readable details about this response
    message: String,
    /// Output that the command printed on stdout
    stdout: String,
    /// Output that the command printed on stderr
    stderr: String,
    /// Total time taken by the command to execute, in milliseconds
    execution_time: u128,
}

/// Specifies whether this request was successful or not
#[derive(Serialize, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Success,
    Error,
}

/// The code of the result, the same as the HTTP response code for this request
#[derive(Serialize_repr, Debug, ToSchema)]
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
    ServiceUnavailable = 503,
    InternalProcessError = 520,
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
