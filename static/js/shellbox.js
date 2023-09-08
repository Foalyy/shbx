const SIGTERM = 15;

let _commandGroups = [];
let _commandNames = [];
let _commands = {};
let _tasksIds = [];
let _tasks = {};
let _openTaskId = null;
let _taskMessagesSource = null;
let _autoscroll = false;

function loadTheme() {
    let theme = Cookies.get('theme');
    if (theme == 'light') {
        setThemeLight();
    } else if (theme == 'dark') {
        setThemeDark();
    }
}

function setThemeLight() {
    $('body').removeClass('dark');
    $('.btn-toggle-theme .fa-moon').removeClass('hidden');
    $('.btn-toggle-theme .fa-sun').addClass('hidden');
    Cookies.set('theme', 'light', { expires: 365, sameSite: 'strict' });
}

function setThemeDark() {
    $('body').addClass('dark');
    $('.btn-toggle-theme .fa-moon').addClass('hidden');
    $('.btn-toggle-theme .fa-sun').removeClass('hidden');
    Cookies.set('theme', 'dark', { expires: 365, sameSite: 'strict' });
}

function toggleTheme() {
    if ($('body').hasClass('dark')) {
        setThemeLight();
    } else {
        setThemeDark();
    }
}

function loadCommands() {
    let request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState == 4) {
            if (this.status == 200) {
                _commandGroups = [];
                _commandNames = [];
                _commands = {};
                let commands = JSON.parse(this.response);
                let container = $('.commands');
                for (let command of commands) {
                    if (_commandGroups.indexOf(command.command_group) < 0) {
                        _commandGroups.push(command.command_group);
                    }
                    _commandNames.push(command.name);
                    _commands[command.name] = command;
                }
                for (let [index, group] of _commandGroups.entries()) {
                    let groupContainer = $('<div class="container commands-group group-' + index + '"></div>')
                    if (group || _commandGroups.length >= 2) {
                        let el = $('<div class="command-group-title"><i class="fa-solid fa-folder-open fa-fw"></i><i class="fa-solid fa-folder-closed fa-fw"></i> <span></span></div>');
                        let name = "Default group";
                        if (group) {
                            name = group;
                        }
                        el.find('span').text(name);
                        el[0].onclick = function () {
                            toggleGroup(index);
                        };
                        groupContainer.append(el);
                    }
                    for (let commandName of _commandNames) {
                        let command = _commands[commandName];
                        if (command.command_group == group) {
                            let el = $('.command-template .command-container').clone();
                            el.prop('id', command.name.trim());
                            el.find('.command-name').text(command.name);
                            el.find('.command-label').text(command.label);
                            el.find('.command-exec').text(command.exec);
                            el.find('.command-run')[0].onclick = function () {
                                openCommand(command.name);
                            };
                            groupContainer.append(el);
                        }
                    }
                    container.append(groupContainer);
                }
                $('.overlay-loading').addClass('hidden');
                loadTasks();
            } else if (this.status == 401 || this.status == 403) {
                $('.overlay-login').removeClass('hidden');
                $('.overlay-loading').addClass('hidden');
            }
        }
    };
    request.open('GET', '/api/commands', true);
    request.send();
}

function loadTasks() {
    let source = new SSE('/api/tasks/stream');
    source.addEventListener('message', function (e) {
        let tasks = {};
        try {
            tasks = JSON.parse(e.data);
        } catch (error) {
            return;
        }
        for (commandName of _commandNames) {
            $('#' + commandName + ' .command-running-tasks').html('');
        }
        _tasksIds = [];
        _tasks = {};
        for (taskId in tasks) {
            let task = tasks[taskId];
            _tasksIds.push(task.id);
            _tasks[task.id] = task;
            let container = $('#' + task.name + ' .command-running-tasks');
            let el = $('<div class="running-task-box-container"><div class="running-task-box accent-fg running-task-open"><div><i class="fa-solid fa-gear fa-spin"></i></div> <div class="running-task-id"></div></div> <div class="running-task-username-box"><div><i class="fa-solid fa-user"></i></div> <div class="running-task-username"></div></div> <button class="terminate flat accent" title="Stop this task"><i class="fa-solid fa-circle-stop"></i></button> <button class="kill flat error hidden" title="Kill this task"><i class="fa-solid fa-skull-crossbones"></i></button></div>');
            el.find('.running-task-id').text(task.id);
            el.find('.running-task-username').text(task.launched_by);
            el.find('.running-task-box')[0].onclick = function () {
                openTask(task.id);
            };
            el.find('.terminate')[0].onclick = function () {
                terminateTask(task.id);
            };
            el.find('.kill')[0].onclick = function () {
                killTask(task.id);
            };
            container.append(el);
        }
        _tasksIds.sort();
    });
    source.addEventListener('readystatechange', function (e) {
        if (e.readyState == 2) {
            $('.overlay-login').removeClass('hidden');
            $('.overlay-loading').addClass('hidden');
        }
    });
}

function openCommand(commandName) {
    $('.main').addClass('blurred');
    $('.task .task-id').text('');
    $('.task .task-id-box').addClass('hidden').removeClass('success-fg error-fg');
    $('.task .task-running').removeClass('hidden');
    $('.task .task-success').addClass('hidden');
    $('.task .task-error').addClass('hidden');
    $('.task .command-run-container').removeClass('hidden');
    $('.task .command-run').removeClass('disabled');
    $('.task .command-output').html('');
    $('.task .command-label').text(_commands[commandName].label);
    $('.task .command-name').text(_commands[commandName].name);
    $('.task .command-exec').text(_commands[commandName].exec);
    $('.task .task-terminate-parent').addClass('hidden');
    $('.task .task-kill-parent').addClass('hidden');
    $('.task .autoscroll-parent').addClass('hidden');
    $('.task .command-run')[0].onclick = function () {
        runCommand(commandName);
    };
    $('.task .autoscroll')[0].onclick = function () {
        $('.task .command-output')[0].scrollTop = 9999999;
        setTimeout(function () {
            setAutoscroll(!_autoscroll);
        }, 100);
    };
    $('.task .task-terminate')[0].onclick = function () {
        terminateTask(_openTaskId);
    };
    $('.task .task-kill')[0].onclick = function () {
        killTask(_openTaskId);
    };
    $('.command-error-box-parent').addClass('hidden');
    $('.command-error').text('');
    $('.overlay-task').removeClass('hidden');
}

function closeCommand() {
    $('.main').removeClass('blurred');
    $('.overlay-task').addClass('hidden');
    _openTaskId = null;
    if (_taskMessagesSource != null) {
        _taskMessagesSource.close();
    }
}

function runCommand(commandName) {
    dialogSetCommandRunning();
    startLoadingTaskMessages('/api/commands/' + commandName + '/stream/events', { method: 'POST' });
}

function openTask(taskId) {
    _openTaskId = taskId;
    openCommand(_tasks[taskId].name);
    dialogSetCommandRunning();
    startLoadingTaskMessages('/api/tasks/' + taskId);
}

function dialogSetCommandRunning() {
    $('.task .command-run').addClass('disabled');
    $('.task .task-id').text('');
    $('.task .task-id-box').addClass('hidden').removeClass('success-fg error-fg');
    $('.task .task-running').removeClass('hidden');
    $('.task .task-success').addClass('hidden');
    $('.task .task-error').addClass('hidden');
    setAutoscroll(true);
}

function startLoadingTaskMessages(url, options) {
    _taskMessagesSource = new SSE(url, options);
    _taskMessagesSource.addEventListener('message', function (e) {
        let message = JSON.parse(e.data);
        if (message.result == 'error') {
            $('.command-error').text(message.message);
            $('.command-error-box-parent').removeClass('hidden');
        } else {
            let taskId = message.task_id;
            if (message.event == 'task_started') {
                _openTaskId = taskId;
            }
            if (taskId == _openTaskId) {
                appendTaskMessage(message);
            }
        }
    });
}

function appendTaskMessage(message) {
    let setTaskStatus = function (status) {
        if (status == 'success' || status == 'error') {
            $('.task .task-id-box').addClass(status + '-fg');
            $('.task .task-running').addClass('hidden');
            if (status == 'success') {
                $('.task .task-success').removeClass('hidden');
                $('.task .task-error').addClass('hidden');
            } else {
                $('.task .task-success').addClass('hidden');
                $('.task .task-error').removeClass('hidden');
            }
        } else {
            $('.task .task-id-box').removeClass('success-fg error-fg');
            $('.task .task-running').removeClass('hidden');
            $('.task .task-success').addClass('hidden');
            $('.task .task-error').addClass('hidden');
        }
    };

    if (message.event == 'task_started') {
        $('.task .command-output').html('');
        let div = $('<div class="diag"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Task " + message.task_id + " started");
        $('.task .command-output').append(div);
        $('.task .command-run-container').addClass('hidden');
        $('.task .task-id').text(message.task_id);
        $('.task .task-id-box').removeClass('hidden');
        $('.task .task-terminate-parent').removeClass('hidden');
        $('.task .task-kill-parent').removeClass('hidden');
        $('.task .autoscroll-parent').removeClass('hidden');

    } else if (message.event == 'stdout' || message.event == 'stderr') {
        let div = $('<div class="' + message.event + '"></div>');
        div.text(message.output);
        $('.task .command-output').append(div);

    } else if (message.event == 'task_exited') {
        let div = $('<div class="diag"><i class="fa-solid fa-gear"></i> <span></span></div>');
        let diag = "Task exited ";
        if (message.exit_code != null) {
            diag += "with exit code " + message.exit_code;
        } else if (message.signal_name != null) {
            diag += "with signal " + message.signal_name + "(" + message.signal + ")";
        } else {
            diag += "without an exit code or signal";
        }
        div.find('span').text(diag);
        $('.task .command-output').append(div);
        if (message.exit_code == 0) {
            setTaskStatus('success');
        } else {
            setTaskStatus('error');
        }

    } else if (message.event == 'kill_signal_sent') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Sending kill signal");
        $('.task .command-output').append(div);

    } else if (message.event == 'signal_sent') {
        let div = $('<div class="diag"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Sending signal " + message.signal_name + "(" + message.signal + ")");
        $('.task .command-output').append(div);

    } else if (message.event == 'task_killed' || message.event == 'task_timeout') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        if (message.event == "task_killed") {
            div.find('span').text("Task killed");
        } else if (message.event == "task_timeout") {
            div.find('span').text("Task timeout after reaching the maximum execution time of " + message.timeout_millis + "ms");
        }
        $('.task .command-output').append(div);
        setTaskStatus('error');

    } else if (message.event == 'error') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Error " + message.code + " : " + message.message);
        $('.task .command-output').append(div);
        setTaskStatus('error');

    } else if (message.event == 'server_shutdown') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Task exiting because the server is shutting down");
        $('.task .command-output').append(div);
        setTaskStatus('error');

    } else if (message.event == 'task_terminated') {
        let div = $('<div class="diag"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Task terminated in " + message.execution_time + "ms");
        $('.task .command-output').append(div);
        $('.task .command-run').removeClass('disabled');
        $('.task .command-run-container').removeClass('hidden');
        $('.task .task-terminate-parent').addClass('hidden');
        $('.task .task-kill-parent').addClass('hidden');
        $('.task .autoscroll-parent').addClass('hidden');
    }

    if (_autoscroll) {
        $('.task .command-output')[0].onscroll = null;
        $('.task .command-output')[0].scrollTop = 9999999;
        setTimeout(function () {
            $('.task .command-output')[0].onscroll = function () {
                setAutoscroll(false);
            };
        }, 100);
    }
}

function killTask(taskId) {
    let request = new XMLHttpRequest();
    request.open('DELETE', '/api/tasks/' + taskId);
    request.send();
}

function terminateTask(taskId) {
    sendSignal(taskId, SIGTERM);
}

function sendSignal(taskId, signal) {
    let request = new XMLHttpRequest();
    request.open('POST', '/api/tasks/' + taskId + '/signal/' + signal);
    request.send();
}

function setAutoscroll(autoscroll) {
    if (autoscroll) {
        $('.autoscroll').addClass('accent');
    } else {
        $('.autoscroll').removeClass('accent');
    }
    _autoscroll = autoscroll;
}

function toggleGroup(index) {
    let el = $('.group-' + index);
    if (el.hasClass('closed')) {
        el.removeClass('closed');
    } else {
        el.addClass('closed');
    }
}

function logout() {
    let request = new XMLHttpRequest();
    request.open('POST', '/logout');
    request.send();
    setTimeout(function () {
        loadCommands();
    }, 100);
}

window.addEventListener("DOMContentLoaded", (event) => {
    loadTheme();
    loadCommands();
});
