[![CI](https://github.com/Foalyy/shbx/actions/workflows/ci.yml/badge.svg)](https://github.com/Foalyy/shbx/actions/workflows/ci.yml)

# ShellBox

<div align="center"><img src="static/img/shbx.svg" width="400"></div>

**ShellBox** / `shbx` is a simple API-based open-source service with a Web UI that simplifies running commands and managing tasks on a remote server. Its main goal is to give some secure and restricted control over a server to other users or systems, without entrusting them with an SSH access.


## TL;DR / summary

- define the commands you want to make available in a static config file
    - **no** possibility for any user to run arbitrary commands not defined in this config file (see the *Security* section below)
    - commands that have been launched and are currently running are refered to as *tasks*
- create new (regular) users using the admin user (automatically created during the first startup)
    - specify a password to access the Web UI
    - a unique API key is also automatically generated for each user
    - give each user access only to the commands they need
    - admins have access to every command and every running task, and can manage users -- users can only see the commands they are allowed to, and can only see and manage the tasks they have launched themselves
- straightforward [API](https://shbx.silica.io/api/doc/) (see also [rapidoc](https://shbx.silica.io/api/rapidoc/)) to launch commands and manage running tasks
    - easily synchronize processes and automate actions between hosts without sharing SSH keys (e.g. by triggering the API with `curl`), to improve isolation and security of your network
- user-friendly Web UI to allow human users to perform the same actions
- tasks run in the background, independently of the request that launched them
    - specify custom timeout delays for each command (to kill them automatically if they take too long), or let them run indefinitely (when launching services)
- launch a command and either (depending on the endpoint used) :
    - wait for it to complete to get back an HTTP response with the output (stdout and stderr) and exit code of the command, in JSON
    - get its output in realtime as a `text/event-stream` of JSON events, compatible with [SSE](https://en.wikipedia.org/wiki/Server-sent_events) (which is what the Web UI uses internally)
    - get its output in realtime as a `text/plain`, easier to read when making a manual `curl` request
- connect back to a running task (using its unique ID) to read its past output and receive future events as a stream
- easily kill a task or send it arbitrary signals, such as `SIGTERM` or `SIGINT`


### Quick jump

- [1/ Installation](#1-installation)
    - [1.1/ (Option A) Install using a release](#11-option-a-install-using-a-release)
    - [1.1/ (Option B) Build from source](#11-option-b-build-from-source)
    - [1.2/ Start as a daemon](#12-start-as-a-daemon)
    - [1.3/ Set up the reverse proxy](#13-set-up-the-reverse-proxy)
    - [1.4/ Updating](#14-updating)
- [2/ Commands](#2-commands)
- [3/ Main configuration file](#3-main-configuration-file)
- [4/ API](#4-api)
- [5/ Web UI](#5-web-ui)
- [6/ Security](#6-security)
- [7/ Acknowledgements](#7-acknowledgements)


## 1/ Installation

### 1.1/ *(Option A)* Install using a release

*Coming soon-ish*

### 1.1/ *(Option B)* Build from source

ShellBox is built with Rust, you will need a Rust compiler to compile it. Here is the simplest way to install one, following [official instructions](https://www.rust-lang.org/tools/install), which will install Cargo (an all-in-one tool to easily compile and run Rust programs) and an up-to-date Rust compiler :

```
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# source "$HOME/.cargo/env"
```

(The default installation options should be fine in most cases but feel free to take a look.)

Get the source code :

```
# cd /var/www/
# git clone https://github.com/Foalyy/shbx.git
# cd shbx
# cargo build --release
```

Cargo will automatically fetch dependencies and compile everything. The app can then be started using :

```
# cargo run --release
```

Create a symlink to the binary into the main directory :

```
# ln -s target/release/shbx shbx
```

You may want to customize the config before starting `shbx`, especially the `ADDRESS` and `PORT` options. Please refer to the *Main configuration file* section below.


### 1.2/ Start as a daemon

A sample `systemd` service file is provided in `utils/shbx.service`. You can customize it as necessary, and then install it using the instructions below. Note that by default this service starts `shbx` as `root` : before installing and starting it, please read the *Security* section below and decide whether you would prefer specifying another user.

```
# vim utils/shbx.service  # Check user (!) and paths
# cp utils/shbx.service /etc/systemd/system/
# systemctl enable --now shbx.service
# systemctl status shbx.service  # Make sure everything looks fine
```

When `shbx` is launched for the first time, it initializes the users database, then creates a default `admin` user with a random password and a new API key and prints them on stdout. Look at the service logs, for instance with `journalctl -u shbx.service`, to get this password and key.

If your OS is not `systemd`-based or your religion forbids you from using `systemd`, adapt the daemon config file accordingly.


### 1.3/ Set up the reverse proxy

ShellBox can run as a standalone, but it is recommended to set it up behind a reverse proxy that will handle HTTPS.

Example using Apache with a Let's Encrypt HTTPS certificate, assuming the service must me accessible at `shbx.example.com`.

Get a certificate :
```
# certbot certonly
```

Create the virtualhost config file for Apache :
```
# vim /etc/apache2/sites-available/shbx.conf
```

You should probably base your config on other existing configs there, but as a reference, here is a simple config file that should work for most cases (remember to customize the domain name) :

```
<IfModule mod_ssl.c>
    <VirtualHost *:443>
        ServerName shbx.example.com
        ServerAdmin admin@example.com

        ProxyPass "/" "http://localhost:8000/"

        ErrorLog ${APACHE_LOG_DIR}/shbx_error.log
        CustomLog ${APACHE_LOG_DIR}/shbx_access.log combined

        SSLEngine on
        SSLCertificateFile  /etc/letsencrypt/live/shbx.example.com/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/shbx.example.com/privkey.pem
    </VirtualHost>

    <VirtualHost *:80>
        ServerName shbx.example.com
        Redirect permanent / https://shbx.example.com/

        ErrorLog ${APACHE_LOG_DIR}/shbx_error.log
        CustomLog ${APACHE_LOG_DIR}/shbx_access.log combined
    </VirtualHost>
</IfModule>
```

Enable and start the virtualhost :

```
# a2ensite shbx.conf
# systemctl reload apache2
```


### 1.4/ Updating

Updating `shbx` to the latest version is easy : 
- stop the service if it is running
- if you have installed using a release :
  - download the latest release
  - extract it over your current installation, to replace the existing files
- if you have built from source :
  - update : `git pull`
  - rebuild : `cargo build --release`
- restart the service


## 2/ Commands

Commands are defined in the `commands.config` file in the app's directory, in TOML format. Start by copying the `commands.config.sample` to customize it, or create a new empty one.

NB : `shbx` automatically reloads `commands.config` when you update it, and does its best to check that commands are valid before applying the changes. If your changes to this file do not appear to be taken into account, take a look at the process output (for instance using `journalctl -u shbx.service`) to check for any error detected in the commands file.

To define a command, start a new section with `[[command]]`. Only two options are mandatory : `NAME`, the handle used to refer to the command through the API, and `EXEC`, the actual command or executable file that you want to run. If you want to use the Web UI, you also probably want to specify a more descriptive `LABEL` (otherwise it defaults to `NAME`). For instance, a simple command to consult the server's uptime (why not) would be :

```
[[command]]
NAME = "uptime"
LABEL = "Read the server's uptime"
EXEC = "uptime"
```

Another common (and more useful) command could be to restart a service :

```
[[command]]
NAME = "restart_mysql"
LABEL = "Restart MySQL"
EXEC = "systemctl restart mysql"
```

Here is the exhaustive list of available options when defining commands :
- `NAME` (mandatory) : internal name for the command, can only contain alphanumeric characters and underscores
- `LABEL` : descriptive name for the command, returned to the users through the API and displayed on the Web UI
- `EXEC` (mandatory) : the command to execute, can be the path to an executable file (with arguments), or a shell command (if `SHELL` is set to `true`)
- `WORKING_DIR` : absolute path to the directory that the command will be launched into
    - if unset and the command points to an executable file, the parent directory of this file is used as the working directory
    - otherwise, the `WORKING_DIR` setting from the main config file is used, which is set to the system's temporary directory (usually `/tmp` on Unix) by default
- `SHELL` (boolean) : if `true`, the command will be launched inside a shell, which allows the use of redirections (`>`), pipes (`|`), env variables (`$HOME`), and so on
    - the shell to use can be specified in the main config file, which is set to `sh -c` by default
- `TIMEOUT_MILLIS` : maximum duration that this command can take to execute, after which the process is killed
    - if unset, the `TIMEOUT_MILLIS` settings from the main config file is used, which is set to 10 seconds by default
- `NO_TIMEOUT` (boolean) : if set to true, the timeout is disabled and the task will be able to run indefinitely (default false)
- `USER` : the user to run this process as
- `GROUP` : the group to run this process as
- `NO_CONCURRENT_EXEC` (boolean) : prevent this command to be launched multiple times in parallel (default false)
    - especially useful for commands that start long-running services, or commands that process files that could get corrupted if accessed concurrently (for instance, a command that recompiles a project)

More examples of a variety of possible commands are available in `commands.config.sample`.


## 3/ Main configuration file

A few general settings can be customized in the `shbx.config` file, located in the app's directory. Start by copying it from `shbx.config.sample`, which is self-documented.

Here is the list of options as a quick reference :
- `ADDRESS` : address to bind the server to, set to "`0.0.0.0`" to serve on all interfaces (**shbx only listens to localhost by default**)
- `PORT` : port to listen on (**8000** by default)
- `DATABASE_PATH` : path to the sqlite file used to store the users (`shbx.sqlite` by default)
- `COMMANDS_PATH` : path to the commands config file (`commands.config` by default)
- `WORKING_DIR` : path to the default working directory to execute the commands into (`/tmp` by default)
- `SHELL` : shell to execute the commands with, for commands that specify `SHELL=true` (`sh -c` by default)
- `TIMEOUT_MILLIS` : default timeout after which a command is killed, in milliseconds


## 4/ API

ShellBox provides a self-served API documentation, based on Swagger UI, on `/api/doc/` (in case you prefer Rapidoc, the documentation is also available in this format on `/api/rapidoc/`). For instance, if you are running `shbx` locally with the default port, point your browser to http://localhost:8000/api/doc/ (or http://localhost:8000/api/rapidoc/). An online version is also available here : https://shbx.silica.io/api/rapidoc/ (or here : https://shbx.silica.io/api/rapidoc/).

Here are a few examples of API requests using `curl`, assuming you have an instance of `shbx` running on `https://shbx.example.com`, and a valid API key set in the `$API_KEY` environment variable. Since `shbx` returns JSON responses in a minimal format, [jq](https://jqlang.github.io/jq/) is used to pretty-print them.

- Read the list of available commands :

`curl -L -H "X-API-Key: $API_KEY" "https://shbx.example.com/api/commands" | jq`

```
[
  {
    "name": "uptime",
    "label": "Read the server's uptime",
    "exec": "uptime"
  },
  {
    "name": "restart_mysql",
    "label": "Restart MySQL",
    "exec": "systemctl restart mysql"
  },
  {
    "name": "rebuild_my_app",
    "label": "Rebuild my custom app",
    "exec": "cargo clean && cargo build"
  }
]
```

- Read the list of tasks currently running :

`curl -L -H "X-API-Key: $API_KEY" "https://shbx.example.com/api/tasks" | jq`

```
[
  {
    "name": "rebuild_my_app",
    "id": "3a8bad38-21b0-40fc-950f-6c01cd60e37c",
    "launched_by": "john",
    "start_timestamp": 1694030155
  }
]
```

- Launch a simple and short command synchronously (note the `-X POST`) :

`curl -L -H "X-API-Key: $API_KEY" -X POST "https://shbx.example.com/api/commands/uptime" | jq`

```
{
  "stdout": " 21:58:01 up 2 days,  2:10,  2 users,  load average: 1.88, 2.02, 1.58\n",
  "stderr": "",
  "exit_code": 0,
  "signal": null,
  "signal_name": null,
}
```

- Launch a longer command with real-time output (note the `-N` to disable buffering) :

`curl -L -N -H "X-API-Key: $API_KEY" -X POST "https://shbx.example.com/api/commands/rebuild_my_app/stream/text"`

```
[shbx] Task started with id 1cf253f3-16f3-4abe-b853-ca42c04f2c66
   Compiling proc-macro2 v1.0.63
   Compiling quote v1.0.29
   Compiling unicode-ident v1.0.10
   Compiling autocfg v1.1.0
   Compiling version_check v0.9.4
...
   Compiling tera v1.19.0
   Compiling rocket_dyn_templates v0.1.0-rc.3
   Compiling my_app v0.1.0 (/home/john/projects/my_app)
    Finished dev [unoptimized + debuginfo] target(s) in 30.75s
[shbx] Task exited with exit code 0
[shbx] Task 1cf253f3-16f3-4abe-b853-ca42c04f2c66 terminated after 31126ms
```

- Connect to a task already running using its ID :

`curl -L -N -H "X-API-Key: $API_KEY" "https://shbx.example.com/api/tasks/e3079fe6-e11e-4400-a56d-6cbe2208227e"`

```
data:{"event":"task_started","task_id":"e3079fe6-e11e-4400-a56d-6cbe2208227e"}

data:{"event":"stdout","task_id":"e3079fe6-e11e-4400-a56d-6cbe2208227e","output":"Service started"}

data:{"event":"stdout","task_id":"e3079fe6-e11e-4400-a56d-6cbe2208227e","output":"Waiting for clients..."}
```

When connecting to a task endpoint, `shbx` sends immediately all the previous events (mainly the past output of the command) as a batch, then keeps streaming the future events to `curl` in real time.

- Send the `SIGTERM(15)` signal to a task using its ID :

`curl -L -H "X-API-Key: $API_KEY" -X POST "https://shbx.example.com/api/tasks/e3079fe6-e11e-4400-a56d-6cbe2208227e/signal/15"`

```
{
  "result": "success",
  "code": 200,
  "message": "Signal SIGTERM sent to task \"e3079fe6-e11e-4400-a56d-6cbe2208227e\""
}
```

- Kill a task using its ID (note the `-X DELETE`) :

`curl -L -H "X-API-Key: $API_KEY" -X DELETE "https://shbx.example.com/api/tasks/e3079fe6-e11e-4400-a56d-6cbe2208227e"`

```
{
  "result": "success",
  "code": 200,
  "message": "Kill signal sent to task \"e3079fe6-e11e-4400-a56d-6cbe2208227e\""
}
```

Internally, this uses a different mechanism than when manually sending the `SIGKILL(9)` signal, though both should lead to the same results.

- Create a new user :

```
curl -L -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" "https://shbx.example.com/api/users" -d '{
    "username": "john",
    "role": "user",
    "password": "Ole7ahxaeh",
    "commands": ["uptime", "restart_mysql", "rebuild_my_app"]
}'
```

```
{
    "result": "success",
    "code": 200,
    "message": "User 'john' created successfully"
}
```


## 5/ Web UI

For users who prefer a graphical interface over the command line (for some obscure reason), `shbx` offers a Web UI. To access it, simply point your browser to the root url, for instance http://localhost:8000/ or `https://shbx.example.com/`. You will be able to easily launch commands and manage running tasks from there.

Note that user management is not yet implemented in this UI and has to be performed through the API.


## 6/ Security

Usually, services exposed to the outside world are ran as a restricted user (such as `www-data`) for security reasons. However, most of the time, at least one of the commands that `shbx` will be configured to run has to execute as `root` (any `systemctl restart ...` for instance). While it would be possible to make these two constraints compatible using custom rules in `/etc/sudoers` for instance, the simplest approach is usually to run `shbx` as `root`. But before installing it and calling it a day, it is always worth discussing the potential security risks involved by running a web service exposed to the Internet as `root`, especially one specifically designed to launch "arbitrary" (see below) commands and processes. This section aims at offering a few arguments and insight to help you make a decision.

Regarding underlying technologies, `shbx` is built in Rust using the [Rocket](https://rocket.rs/) web framework. Rust is a compiled, memory-safe language that offers many strong guarantees against common programming mistakes, making it fairly robust against usual vulnerabilities of, both, interpreted web languages (code injection, ...), and compiled languages (buffer overflows, pointer mishandling, ...). Rocket builds on top of Rust's features to provide interesting compile-time guarantees, for instance regarding authentification mechanisms (more information here : https://rocket.rs/v0.5-rc/guide/requests/#guard-transparency).

Regarding user sessions and API keys : when logging in to the Web UI, `shbx` generates a temporary "session" API Key that gets automatically revoked after 10 days of inactivity. This key is sent to the client as cookie both authenticated and encrypted, using a 256-bit key generated during the first startup and stored inside the `.secret` file. See here for more information : https://rocket.rs/v0.5-rc/guide/requests/#private-cookies.

Each command can be ran as another, less-privileged user and group. Use this feature to restrict the scope of commands as much as possible, especially when using `shbx` to launch another service exposed to the Internet, or any kind of command that processes arbitrary (user-provided) files or data.

Most importantly, available commands are statically defined inside the `commands.config` file, that is assumed to be protected sensibly. No API endpoint is available to run actually arbitrary (user-provided) commands, or to upload files. User-controlled inputs are mainly limited to the command_name and task_id text inputs, which makes attack surface minimal.

Of course, ShellBox is also an open source project. Feel free to read the source code and open an issue for any relevant security concern you may have.

With all of this in mind, it is up to you to decide whether it's worth running `shbx` as `root` depending on the security requirements and threat model of your specific application.


## 7/ Acknowledgements

Main icon based on `terminal` by Font-Awesome : [https://fontawesome.com/icons/terminal?s=solid&f=classic](https://fontawesome.com/icons/terminal?s=solid&f=classic)

Backend built using the excellent Rust web framework Rocket :
- [https://rocket.rs/](https://rocket.rs/)
- [https://github.com/SergioBenitez/Rocket/](https://github.com/SergioBenitez/Rocket/)