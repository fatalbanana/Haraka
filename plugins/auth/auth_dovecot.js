// Auth against Dovecot SASL
var sock = require('./line_socket');

exports.register = function () {
    var plugin = this;
    plugin.load_dovecot_ini();
};

exports.load_dovecot_ini = function () {
    var plugin = this;
    plugin.cfg = plugin.config.get('dovecot.ini', function () {
        plugin.load_dovecot_ini();
    });

    var defaults = {
        hostname: 'localhost',
        port: 12345,
        service: 'imap',
    };

    for (var key in defaults) {
       if (plugin.cfg.main[key]) continue;
       plugin.cfg.main[key] = defaults[key]; 
    }

};

exports.pool = {};

exports.advertise_auth = function(next, connection, methods) {
        if (methods && methods.length > 1) {
           connection.capabilities.push('AUTH ' + methods.join(' '));
           connection.notes.allowed_auth_methods = methods;
        }
        return next();
};

exports.hook_capabilities = function (next, connection) {
    var plugin = this;
    var methods = [];

    if (!server.notes.dovecot_auth_methods) {
        plugin.get_methods(next, connection, plugin.advertise_auth);
    } else {
        plugin.advertise_auth(next, connection, server.notes.dovecot_auth_methods);
    }
};

exports.get_methods = function(next, connection, advertise_auth) {
    var plugin = this;
    var version;
    var methods = [];
    var socket = new sock.Socket();
    socket.connect(plugin.cfg.main.port, plugin.cfg.main.hostname);

    socket.on('line', function(line) {
        var res = line.split('\t');
        switch(res[0].trim()) {
           case 'MECH':
               methods.push(res[1]);
               break;
           case 'VERSION':
               version = res[1] + '.' + res[2];
               break;
           case 'DONE':
               if (version != 1.1) {
                   connection.logerror('Got wrong protocol version from Dovecot: ' + version);
                   methods = [];
               }
               server.notes.dovecot_auth_methods = methods.sort();
               socket.end();
               return advertise_auth(next, connection, methods);
        }
    });
};

exports.hook_unrecognized_command = function (next, connection, params) {
    var plugin = this;
    if(params[0].toUpperCase() === 'AUTH' && params[1]) {
        connection.notes.authenticating = true;
    }
    if (!connection.notes.authenticating) { return next(); }
    if (params[1]) {
        var split = params[1].split(' ');
    } else {
        var split = [];
    }
    if (plugin.pool[connection.uuid]) {
        var socket = plugin.pool[connection.uuid];
        if (!socket.writable) {
            socket.connect(plugin.cfg.main.port, plugin.cfg.main.hostname);
        }
        if (params[0] != 'AUTH') {
            socket.write('CONT\t1\t'+params[0]+'\n');
            return next(OK);
        }
    } else {
        var socket = new sock.Socket();
        socket.connect(plugin.cfg.main.port, plugin.cfg.main.hostname);
        plugin.pool[connection.uuid] = socket;
    }

    socket.on('end', function() {
        delete(plugin.pool[connection.uuid]);
    });

    var version;
    var methods = [];

    socket.on('line', function(line) {
        var res = line.split('\t');
        switch(res[0].trim()) {
           case 'DONE':
               if (version != 1.1) {
                    connection.logerror('Got wrong version number from Dovecot');
               }
               var found_method = false;
               methods.forEach(function(method) {
                   if (split[0] == method) {
                       found_method = true;
                   }
               });
               if (!found_method) {
                   connection.logerror('Client tried unsupported auth scheme: ' + split[0]);
               }
               methods = methods.sort();
               if (methods != server.notes.dovecot_auth_methods) {
                   connection.loginfo('Change in Dovecot auth methods detected- refreshing');
                   server.notes.dovecot_auth_methods = methods;
               }
               if((version != 1.1) || (!found_method)) {
                   connection.respond(535, 'Cannot authenticate', function() {
                        connection.notes.authenticating = false;
                        connection.reset_transaction(function() {
                            socket.end();
                        });
                    });
               } else {
                   socket.write('VERSION\t1\t1\nCPID\t'+process.pid+'\n');
                   socket.write('AUTH\t1\t'+split[0]+'\tservice='+plugin.cfg.main.service+'\tsecured');
                   if(split.length === 2) {
                       socket.write('\tresp='+split[1]);
                   }
                   socket.write('\n');
               }
               break;
           case 'CONT':
               connection.respond(334, res[2], function () {
               });
               break;
           case 'OK':
               if (res[2]) {
                   var username = res[2].split('=')[1];
               }
               if (username) {
                   connection.respond(235, 'Authentication successful', function() {
                       connection.notes.auth_user = username;
                       connection.notes.authenticating = false;
                       socket.end();
                   });
               } else {
                    connection.logerror('Authenticated OK but couldnt get username - failing auth');
                    connection.respond(535, 'Cannot authenticate', function() {
                        connection.notes.authenticating = false;
                        connection.reset_transaction(function() {
                            socket.end();
                        });
                    });
               }
               break;
           case 'FAIL':
               connection.respond(535, 'Authentication failed', function() {
                   connection.notes.authenticating = false;
                   connection.reset_transaction(function() {
                       socket.end();
                   });
               });
               break;
           case 'MECH':
               methods.push(res[1]);
               break;
           case 'VERSION':
               version = res[1] + '.' + res[2];
               break;
           default:
               break;
        }; 
    });
    return next(OK);
}
