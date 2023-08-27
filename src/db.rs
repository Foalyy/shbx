use crate::{
    api::ApiKey,
    command::{CommandName, Commands},
    user::{NewUser, PlaintextPassword, UpdatedUser, User, UserRole},
    Error,
};
use rocket::{fairing, serde::json::serde_json, Build, Rocket};
use rocket_db_pools::{
    sqlx::{self, pool::PoolConnection, QueryBuilder, Row, Sqlite},
    Database,
};
use std::str::FromStr;

const SCHEMA: &str = "
    DROP TABLE IF EXISTS user;

    CREATE TABLE user (
        username VARCHAR(255) PRIMARY KEY,
        password VARCHAR(255),
        api_key VARCHAR(255),
        role VARCHAR(32),
        commands TEXT
    );
";

#[derive(Database)]
#[database("shbx")]
pub struct DB(pub sqlx::SqlitePool);

/// Fairing callback that checks if the database has already been filled with the `user`
/// table and if not, executes SCHEMA to initialize it
pub async fn init_schema(rocket: Rocket<Build>) -> fairing::Result {
    // Make sure the database has been initialized (fairings have been attached in the correct order)
    if let Some(db) = DB::fetch(&rocket) {
        let db = &db.0;

        // Check the `sqlite_master` table for a table named `user`
        let query_result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='user';")
                .fetch_optional(db)
                .await;
        match query_result {
            // The table already exists, we can proceed with liftoff
            Ok(Some(_)) => Ok(rocket),

            // The table doesn't exist, try to import the schema to create it
            Ok(None) => {
                print!("Database is empty, creating schema... ");

                // Split the schema to import into individual queries
                let sql_queries = SCHEMA
                    .split(';')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty());
                for sql_query in sql_queries {
                    let query_result = sqlx::query(sql_query).execute(db).await;
                    if let Err(error) = query_result {
                        println!();
                        eprintln!("Error, unable to execute a query from SCHEMA :");
                        eprintln!("{sql_query}");
                        eprintln!("Result : {error}");
                        return Err(rocket);
                    }
                }
                println!("success");

                // Insert a default 'admin' user into the newsly created database
                match db.acquire().await {
                    Ok(mut db_conn) => {
                        let password = PlaintextPassword::random(10);
                        let admin = NewUser {
                            username: "admin".to_string(),
                            role: UserRole::Admin,
                            password: password.clone(),
                            commands: Vec::new(),
                        };
                        match insert_user(&mut db_conn, admin).await {
                            Ok(api_key) => println!(
                                "Admin user created : login with user 'admin' and password '{password}', or use API key '{api_key}'",
                            ),
                            Err(error) => {
                                eprintln!("Error, unable to create the admin user : {error}");
                                return Err(rocket);
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "Error : unable to acquire a connection to the database : {error}"
                        );
                        return Err(rocket);
                    }
                }

                Ok(rocket)
            }

            // Something went wrong when checking `sqlite_master`, we'll have to scrub the launch
            Err(e) => {
                eprintln!("Error, unable to access database to check schema : {e}");
                Err(rocket)
            }
        }
    } else {
        Err(rocket)
    }
}

/// Get the list of users
pub async fn list_users(
    db_conn: &mut PoolConnection<Sqlite>,
    commands: &Commands,
) -> Result<Vec<User>, Error> {
    Ok(sqlx::query("SELECT * FROM user;")
        .fetch_all(&mut *db_conn)
        .await?
        .iter()
        .filter_map(|row| {
            let username = row.get("username");
            let role = UserRole::from_str(row.get::<&str, _>("role"))
                .map_err(|error| {
                    eprintln!("Warning : invalid role for user {username} : {error}");
                    error
                })
                .ok()?;
            let user_commands = match role {
                UserRole::Admin => commands.iter().map(|(name, _)| name.clone()).collect(),
                UserRole::User => {
                    let mut user_commands =
                        serde_json::from_str::<Vec<CommandName>>(row.get("commands"))
                            .map_err(|error| {
                                eprintln!(
                                    "Warning : invalid commands for user {username} : {error}"
                                );
                                error
                            })
                            .ok()?;
                    user_commands.retain(|name| commands.contains_key(name));
                    user_commands
                }
            };
            Some(User {
                username,
                role,
                hashed_password: None,
                api_key: row.get::<&str, _>("api_key").into(),
                session_key: None,
                commands: user_commands,
            })
        })
        .collect::<Vec<User>>())
}

/// Insert a user in the database
pub async fn insert_user(
    db_conn: &mut PoolConnection<Sqlite>,
    new_user: NewUser,
) -> Result<ApiKey, Error> {
    let api_key = ApiKey::new();
    let mut query_builder =
        QueryBuilder::new("INSERT INTO user(username, password, api_key, role, commands) VALUES (");
    let mut fields = query_builder.separated(", ");
    fields.push_bind(new_user.username);
    fields.push_bind(new_user.password.hash_with_random_salt());
    fields.push_bind(api_key.to_string());
    fields.push_bind(new_user.role.to_string());
    fields.push_bind(serde_json::to_string(&new_user.commands)?);
    fields.push_unseparated(")");
    let query = query_builder.build();
    query.execute(&mut *db_conn).await?;
    Ok(api_key)
}

/// Find a user from the given username
pub async fn get_user(
    db_conn: &mut PoolConnection<Sqlite>,
    commands: &Commands,
    username: &String,
) -> Result<Option<User>, Error> {
    let query_result = sqlx::query("SELECT * FROM user WHERE username=?;")
        .bind(username)
        .fetch_optional(&mut *db_conn)
        .await?;
    match query_result {
        Some(row) => {
            let username = row.get("username");
            let role = UserRole::from_str(row.get::<&str, _>("role")).map_err(|error| {
                eprintln!("Warning : invalid role for user {username} : {error}");
                error
            })?;
            let mut user_commands = serde_json::from_str::<Vec<CommandName>>(row.get("commands"))
                .map_err(|error| {
                eprintln!("Warning : invalid commands for user {username} : {error}");
                error
            })?;
            user_commands.retain(|name| commands.contains_key(name));
            Ok(Some(User {
                username,
                role,
                hashed_password: row.get("password"),
                api_key: row.get::<&str, _>("api_key").into(),
                session_key: None,
                commands: user_commands,
            }))
        }
        None => Ok(None),
    }
}

/// Find a user from the given api key
pub async fn find_user_from_api_key(
    db_conn: &mut PoolConnection<Sqlite>,
    commands: &Commands,
    api_key: &ApiKey,
) -> Result<Option<User>, Error> {
    let query_result = sqlx::query("SELECT * FROM user WHERE api_key=?;")
        .bind(api_key.to_string())
        .fetch_optional(&mut *db_conn)
        .await?;
    match query_result {
        Some(row) => {
            let username = row.get("username");
            let role = UserRole::from_str(row.get::<&str, _>("role")).map_err(|error| {
                eprintln!("Warning : invalid role for user {username} : {error}");
                error
            })?;
            let mut user_commands = serde_json::from_str::<Vec<CommandName>>(row.get("commands"))
                .map_err(|error| {
                eprintln!("Warning : invalid commands for user {username} : {error}");
                error
            })?;
            user_commands.retain(|name| commands.contains_key(name));
            Ok(Some(User {
                username,
                role,
                hashed_password: row.get("password"),
                api_key: row.get::<&str, _>("api_key").into(),
                session_key: None,
                commands: user_commands,
            }))
        }
        None => Ok(None),
    }
}

/// Update a user in the database
pub async fn update_user(
    db_conn: &mut PoolConnection<Sqlite>,
    username: String,
    updated_user: UpdatedUser,
) -> Result<(), Error> {
    let mut query_builder = QueryBuilder::new("UPDATE user SET ");
    let mut first = true;
    if let Some(password) = updated_user.password {
        query_builder.push("password=");
        query_builder.push_bind(password.hash_with_random_salt());
        first = false;
    }
    if let Some(role) = updated_user.role {
        if !first {
            query_builder.push(",");
        }
        query_builder.push("role=");
        query_builder.push_bind(role.to_string());
        first = false;
    }
    if let Some(commands) = updated_user.commands {
        if !first {
            query_builder.push(",");
        }
        query_builder.push("commands=");
        query_builder.push_bind(serde_json::to_string(&commands)?);
        first = false;
    }
    query_builder.push(" WHERE username=");
    query_builder.push_bind(username.clone());
    query_builder.push(";");
    if !first {
        // Only execute the query if some fields were modified
        let query = query_builder.build();
        let result = query.execute(&mut *db_conn).await?;
        if result.rows_affected() > 0 {
            Ok(())
        } else {
            Err(Error::InvalidUser(username))
        }
    } else {
        Ok(())
    }
}

/// Delete a user from the database
pub async fn delete_user(
    db_conn: &mut PoolConnection<Sqlite>,
    username: String,
) -> Result<(), Error> {
    let mut query_builder = QueryBuilder::new("DELETE FROM user WHERE username=");
    query_builder.push_bind(username.clone());
    query_builder.push(";");
    let result = query_builder.build().execute(&mut *db_conn).await?;
    if result.rows_affected() > 0 {
        Ok(())
    } else {
        Err(Error::InvalidUser(username))
    }
}
