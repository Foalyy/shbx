use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};

use crate::{api, command, user};

/// Auto-generated OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "ShellBox (shbx) API documentation",
        description = "This API can be used to interface with shbx to launch commands and manage running tasks.",
    ),
    paths(
        api::route_commands_list,
        api::route_exec_command,
        api::route_exec_command_stream_events,
        api::route_exec_command_stream_text,
        api::route_tasks_list,
        api::route_tasks_list_stream,
        api::route_task_kill,
        api::route_users_list_all,
        api::route_user_create,
        api::route_user_get,
        api::route_user_update,
        api::route_user_revoke_api_key,
        api::route_user_delete,
    ),
    components(
        schemas(
            command::Command,
            command::CommandResult,
            command::Task,
            command::TaskId,
            api::MessageResponse,
            api::MessageResponseWithOutput,
            api::ResultCode,
            api::ResultStatus,
            user::User,
            user::UserRole,
            user::NewUser,
            user::UpdatedUser,
        ),
    ),
    tags(
        (name = "Commands", description = "Endpoints for commands"),
        (name = "Tasks", description = "Endpoints for currently-running tasks"),
        (name = "Users", description = "Endpoints for users"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap(); // we can unwrap safely since there already is components registered.
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-KEY"))),
        )
    }
}
