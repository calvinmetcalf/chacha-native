var Chacha = require('./addon');
var key = new Buffer(32);
key.fill(0);
var iv = new Buffer(8);
iv.fill(0);
var obj = new Chacha(key, iv);
var key2 = new Buffer(32);
key2.fill(0);
var iv2 = new Buffer(8);
iv2.fill(0);
var obj2 = new Chacha(key2, iv2);
var zero = new Buffer(7);
zero.fill(0);
console.log( obj2.update(obj.update(zero)) ); // 11
console.log(  obj2.update(obj.update(zero))  ); // 12
console.log(  obj2.update(obj.update(zero.slice(3)))  ); // 13