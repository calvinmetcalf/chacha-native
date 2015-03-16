'use strict';
var stream = require('stream');
var inherits = require('inherits');
var Binding = require('bindings')('chacha20poly1305.node').Poly;
module.exports = PolyStream;
inherits(PolyStream, stream.Transform);
function PolyStream(key) {
  this.binding = new Binding(key);
}
[
  '_readableState',
  '_writableState',
  '_transformState'
].forEach(function(prop) {
  Object.defineProperty(PolyStream.prototype, prop, {
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
PolyStream.prototype.update = function (data) {
  this.binding.update(data);
  return this;
};

PolyStream.prototype._transform = function(data, _, next) {
  this.binding.update(data);
  next();
};
PolyStream.prototype._flush = function (next) {
  this.push(this.binding.finish());
  next();
};
PolyStream.prototype.digest = function () {
  return this.binding.finish();
};
