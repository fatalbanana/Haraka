'use strict';

var Address      = require('address-rfc2821');
var fixtures     = require('haraka-test-fixtures');
var http         = require('http');

var Connection   = fixtures.connection;
var stub         = fixtures.stub.stub;

var _set_up = function (done) {

    this.plugin = new fixtures.plugin('rspamd');
    this.plugin.cfg = { main: { } };

    this.connection = Connection.createConnection();
    this.connection.transaction = stub;
    this.connection.transaction.notes = {};
    this.fakerspamd = http.createServer();
    this.fakerspamd.listen(0);

    done();
};

exports.register = {
    setUp : _set_up,
    'loads the rspamd plugin': function (test) {
        test.expect(1);
        test.equal('rspamd', this.plugin.name);
        test.done();
    },
    'loads rspamd.ini': function (test) {
        test.expect(3);
        this.plugin.load_rspamd_ini();
        test.equal(this.plugin.cfg.main.host, 'localhost');
        test.equal(this.plugin.cfg.main.port, 11333);
        test.equal(this.plugin.cfg.main.add_headers, 'sometimes')
        test.done();
    }
/*    'reconfigure rspamd': function (test) {
        test.expect(3);
        this.plugin.cfg.main.host = fakerspamd.address().address;
        this.plugin.cfg.main.port = fakerspamd.address().port;
        test.done();
    },
*/
};
