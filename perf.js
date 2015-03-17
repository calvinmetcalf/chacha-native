
var crypto = require('crypto');
var Binding = require('bindings')('chacha20poly1305.node');

var Simd = Binding.Chacha;
var Linear = Binding.Chacha2;

var simdTime = 0;
var liniarTime = 0;

function test(num){
	var key = crypto.randomBytes(32);
	var iv = crypto.randomBytes(12);
	var data = crypto.randomBytes(1000);
	var simd = new Simd(key, iv);
	var simdStart = Date.now();
	var out = simd.update(data);
	simdTime += (Date.now() - simdStart);
	var linear = new Linear(key, iv);
	var linearStart = Date.now();
	var out2 = linear.update(data);
	liniarTime += (Date.now() - linearStart);
	if (!num) {
		console.log('simd', simdTime);
		console.log('liniar', liniarTime);
	} else {
		setImmediate(function () {
			test(num - 1);
		})
	}
}
test(100000);