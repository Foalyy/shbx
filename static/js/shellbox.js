let _commandNames = [];
let _commands = {};
let _tasksIds = [];
let _tasks = {};
let _runningTasks = {};
let _currentTaskId = null;
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
    Cookies.set('theme', 'light', { expires: 365 });
}

function setThemeDark() {
    $('body').addClass('dark');
    $('.btn-toggle-theme .fa-moon').addClass('hidden');
    $('.btn-toggle-theme .fa-sun').removeClass('hidden');
    Cookies.set('theme', 'dark', { expires: 365 });
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
                _commandNames = [];
                _commands = {};
                let commands = JSON.parse(this.response);
                let container = $('.commands');
                for (let command of commands) {
                    _commandNames.push(command.name);
                    _commands[command.name] = command;
                    let el = $('.command-template .command-container').clone();
                    el.prop('id', command.name.trim());
                    el.find('.command-name').text(command.name);
                    el.find('.command-label').text(command.label);
                    el.find('.command-exec').text(command.exec);
                    el.find('.command-run')[0].onclick = function () {
                        openCommand(command.name);
                    };
                    container.append(el);
                }
                $('.overlay-loading').addClass('hidden');
                setTimeout(function () {
                    loadTasks();
                }, 100);
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
    let request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState == 4) {
            if (this.status == 200) {
                let tasks = JSON.parse(this.response);
                let newTasksIds = [];
                for (task of tasks) {
                    newTasksIds.push(task.id);
                }
                newTasksIds.sort();
                let update = false;
                if (_tasksIds.length == newTasksIds.length) {
                    for (let i = 0; i < _tasksIds.length; i++) {
                        if (_tasksIds[i] != newTasksIds[i]) {
                            update = true;
                            break;
                        }
                    }
                } else {
                    update = true;
                }
                if (update) {
                    for (commandName of _commandNames) {
                        $('#' + commandName + ' .command-running-tasks').html('');
                    }
                    _tasksIds = [];
                    _tasks = {};
                    for (let task of tasks) {
                        _tasksIds.push(task.id);
                        _tasks[task.id] = task;
                        let container = $('#' + task.name + ' .command-running-tasks');
                        let el = $('<div class="running-task-box-container"><div class="running-task-box"><div><i class="fa-solid fa-gear fa-spin"></i></div> <div class="running-task-id"></div></div> <button class="kill flat error" title="kill"><i class="fa-solid fa-skull-crossbones"></i></button></div>');
                        el.find('.running-task-id').text(task.id);
                        if (_runningTasks[task.id]) {
                            el.find('.running-task-box').addClass('accent-fg').addClass('running-task-open');
                            el.find('.running-task-box')[0].onclick = function () {
                                openTask(task.id);
                            };
                        }
                        el.find('.kill')[0].onclick = function () {
                            killTask(task.id);
                        };
                        container.append(el);
                    }
                }
                _tasksIds.sort();
            }
        }
    };
    request.open('GET', '/api/tasks', true);
    request.send();
}

function openTask(taskId) {
    _currentTaskId = taskId;
    let task = _runningTasks[taskId];
    let commandName = task.commandName;
    openCommand(commandName);
    for (message of task.messages) {
        appendTaskMessage(message);
    }
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
    $('.task .task-kill')[0].onclick = function () {
        killTask(_currentTaskId);
    };
    $('.command-error-box-parent').addClass('hidden');
    $('.command-error').text('');
    $('.overlay-task').removeClass('hidden');
}

function closeCommand() {
    $('.main').removeClass('blurred');
    $('.overlay-task').addClass('hidden');
    _currentTaskId = null;
}

function runCommand(commandName) {
    $('.task .command-run').addClass('disabled');
    $('.task .task-id').text('');
    $('.task .task-id-box').addClass('hidden').removeClass('success-fg error-fg');
    $('.task .task-running').removeClass('hidden');
    $('.task .task-success').addClass('hidden');
    $('.task .task-error').addClass('hidden');
    setAutoscroll(true);
    var source = new SSE('/api/commands/' + commandName + '/stream/events', { method: 'POST', start: false });
    source.addEventListener('message', function (e) {
        var message = JSON.parse(e.data);
        if (message.result == 'error') {
            $('.command-error').text(message.message);
            $('.command-error-box-parent').removeClass('hidden');
        } else {
            let taskId = message.task_id;
            if (message.event == 'task_started') {
                _currentTaskId = taskId;
                loadTasks();
            }
            if (_runningTasks[taskId] == undefined) {
                _runningTasks[taskId] = {
                    commandName: commandName,
                    messages: [],
                };
            }
            _runningTasks[taskId].messages.push(message);
            if (taskId == _currentTaskId) {
                appendTaskMessage(message);
            }
        }
    });
    source.stream();
}

function appendTaskMessage(message) {
    let taskEndedCommon = function() {
        $('.task .command-run').removeClass('disabled');
        $('.task .command-run-container').removeClass('hidden');
        $('.task .task-kill-parent').addClass('hidden');
        $('.task .autoscroll-parent').addClass('hidden');
    };
    let setTaskStatus = function(status) {
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
        $('.task .task-kill-parent').removeClass('hidden');
        $('.task .autoscroll-parent').removeClass('hidden');
    } else if (message.event == 'stdout' || message.event == 'stderr') {
        let div = $('<div class="' + message.event + '"></div>');
        div.text(message.output);
        $('.task .command-output').append(div);
    } else if (message.event == 'task_finished') {
        let div = $('<div class="diag"><i class="fa-solid fa-gear"></i> <span></span></div>');
        let diag = "Task finished ";
        if (message.exit_code == null) {
            diag += "without an exit code";
        } else {
            diag += "with exit code " + message.exit_code;
        }
        diag += " in " + message.execution_time + "ms";
        div.find('span').text(diag);
        $('.task .command-output').append(div);
        if (message.exit_code == 0) {
            setTaskStatus('success');
        } else {
            setTaskStatus('error');
        }
        taskEndedCommon();
    } else if (message.event == 'task_killed' || message.event == 'task_timeout') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        if (message.event == "task_killed") {
            div.find('span').text("Task killed after " + message.execution_time + "ms");
        } else if (message.event == "task_timeout") {
            div.find('span').text("Task timeout after " + message.execution_time + "ms");
        }
        $('.task .command-output').append(div);
        setTaskStatus('error');
        taskEndedCommon();
    } else if (message.event == 'error') {
        let div = $('<div class="diag error-fg"><i class="fa-solid fa-gear"></i> <span></span></div>');
        div.find('span').text("Error " + message.code + " : " + message.message);
        $('.task .command-output').append(div);
        setTaskStatus('error');
        taskEndedCommon();
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
    setTimeout(function () {
        loadTasks();
    }, 100);
}

function setAutoscroll(autoscroll) {
    if (autoscroll) {
        $('.autoscroll').addClass('accent');
    } else {
        $('.autoscroll').removeClass('accent');
    }
    _autoscroll = autoscroll;
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
