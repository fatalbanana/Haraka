// Auth against Dovecot SASL
var sock = require('./line_socket');
var utils = require('./utils');

var LOGIN_STRING1 = 'VXNlcm5hbWU6'; //UserLogin: base64 coded
var LOGIN_STRING2 = 'UGFzc3dvcmQ6'; //Password: base64 coded

exports.register = function () {
    var plugin = this;
    plugin.inherits('auth/auth_base');
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

exports.hook_capabilities = function (next, connection) {
    var plugin = this;

    var methods = ['PLAIN', 'LOGIN'];
    if (methods && methods.length > 0) {
        connection.capabilities.push('AUTH ' + methods.join(' '));
        connection.notes.allowed_auth_methods = methods;
    }
    next();
};

exports.auth_plain = function(next, connection, params) {
    return this.try_dovecot_auth(next, connection, params, 'PLAIN');
};

exports.auth_login = function(next, connection, params) {
    var plugin = this;
    if ((!connection.notes.auth_login_asked_login && params[0]) ||
        (connection.notes.auth_login_asked_login && !connection.notes.auth_login_userlogin))
    {
        var login = params[0];
        connection.respond(334, LOGIN_STRING2, function () {
            connection.notes.auth_login_userlogin = login;
            connection.notes.auth_login_asked_login = true;
            return next(OK);
        });
        return;
    }

    if (connection.notes.auth_login_userlogin) {
        connection.notes.auth_login_password = params[0];
        return plugin.try_dovecot_auth(next, connection, params, 'LOGIN');
    }

    connection.respond(334, LOGIN_STRING1, function () {
        connection.notes.auth_login_asked_login = true;
        return next(OK);
    });
};

exports.try_dovecot_auth = function(next, connection, params, scheme) {
    var plugin = this;
    var found_scheme = false;
    var headers = {
        mech: {},
    };
    var socket = new sock.Socket();
    socket.connect(plugin.cfg.main.port, plugin.cfg.main.hostname);

    socket.on('line', function(line) {
        var res = line.split('\t');
        switch(res[0].trim()) {
           case 'VERSION':
               headers.version = res[1] + '.' + res[2];
               break;
           case 'MECH':
               if (res[1] == scheme) {
                   found_scheme = true;
               }
               break;
           case 'DONE':
               if (!found_scheme) {
                   connection.logerror('Dovecot cant support requested scheme');
                   connection.respond(535, 'Cannot authenticate', function() {
                       return next(OK);
                   });
                   break;
               }
               if (headers.version != 1.1) {
                   connection.logerror('Got wrong protocol version from Dovecot: ' + headers.version);
                   connection.respond(535, 'Cannot authenticate', function() {
                       return next(OK);
                   });
                   break;
               }
               socket.write('VERSION\t1\t1\nCPID\t'+process.pid+'\n');
               switch (scheme) {
                   case 'PLAIN':
                       socket.write('AUTH\t1\tPLAIN\tservice='+plugin.cfg.main.service+'\tsecured\tresp='+params+'\n');
                       break;
                   case 'LOGIN':
                       socket.write('AUTH\t1\tLOGIN\tservice='+plugin.cfg.main.service+'\tsecured\tresp='+connection.notes.auth_login_userlogin+'\n');
                       break;
                   default:
                       connection.logerror('No handler for scheme: ' + scheme);
                       connection.respond(535, 'Cannot authenticate', function() {
                           return next(OK);
                       });
                       break;
               }
               break;
           case 'CONT':
               socket.write('CONT\t1\t' + connection.notes.auth_login_password + '\n');
               break;
           case 'OK':
               connection.respond(235, 'Authentication successful', function() {
                   if (scheme == 'PLAIN') {
                       var credentials = utils.unbase64(params[0]).split(/\0/);
                       connection.notes.auth_user = credentials[1];
                       connection.notes.auth_passwd = credentials[2];
                   } else if (scheme == 'LOGIN') {
                       connection.notes.auth_user = utils.unbase64(connection.notes.auth_login_userlogin);
                       connection.notes.auth_passwd = utils.unbase64(connection.notes.auth_login_password);
                   }
                   return next(OK);
               });
               break;
           case 'FAIL':
               connection.respond(535, 'Authentication failed', function() {
                   connection.reset_transaction(function() {
                       return next(OK);
                   });
               });
               break;
           default:
               break;
        }; 
    });

}
