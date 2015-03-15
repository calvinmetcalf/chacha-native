var Chacha = require('./addon');
var Chachajs = require('chacha/chachastream');
var test = require('tape');
var crypto = require('crypto');

var i = 0;
function testIt(t) {
	t.plan(2);
	var key = crypto.randomBytes(32);
	var iv =crypto.randomBytes(12);
	var c = new Chacha(key, iv);
	var c2 = new Chacha(key, iv);
	var js = new Chachajs(key, iv);
	var data = new Buffer(93);
	data.fill(0);
	var js4 = js.update(data).toString('hex');
	t.equals(c.update(data).toString('hex'), js4);
	t.equals(c2.update(data).toString('hex'), js4);
}
while (i++ < 10) {
	test('round ' + i, testIt)
}