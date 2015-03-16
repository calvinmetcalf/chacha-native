'use strict';
var stream = require('stream');
var inherits = require('inherits');
var Binding = require('bindings')('addon').Chacha;
module.exports = ChaChaStream;
inherits(ChaChaStream, stream.Transform);
function ChaChaStream(key, iv) {
  this.binding = new Binding(key, iv);
}
[
  '_readableState',
  '_writableState',
  '_transformState'
].forEach(function(prop) {
  Object.defineProperty(ChaChaStream.prototype, prop, {
    get: function() {
      stream.Transform.call(this);
      return this[prop];
    },
    set: function(val) {
      Object.defineProperty(this, prop, {
        value: val,
        enumerable: true,
        configurable: true,
        writable: true
      });
    },
    configurable: true,
    enumerable: true
  });
});
ChaChaStream.prototype.update = function (data) {
  return this.binding.update(data);
};

ChaChaStream.prototype._transform = function(data, _, next) {
  this.push(this.binding.update(data));
  next();
};
