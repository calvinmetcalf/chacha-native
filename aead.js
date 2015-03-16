'use strict';
var stream = require('stream');
var inherits = require('inherits');
var Binding = require('bindings')('addon').AEAD;
module.exports = AEAD;
inherits(AEAD, stream.Transform);
function AEAD(key, iv, decrypt) {
  this.binding = new Binding(key, iv, decrypt);
  this._tag = void 0;
  this._decrypt = !!decrypt;
}
[
  '_readableState',
  '_writableState',
  '_transformState'
].forEach(function(prop) {
  Object.defineProperty(AEAD.prototype, prop, {
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
AEAD.prototype.update = function (data) {
  return this.binding.update(data);
};

AEAD.prototype._transform = function(data, _, next) {
  this.push(this.binding.update(data));
  next();
};
AEAD.prototype.final = function () {
  if (this._decrypt && !this._tag) {
    throw new Error('invalid state');
  }
  if (this._decrypt) {
    this.binding.finish(this._tag);
    this._tag = void 0;
  } else {
    this._tag = this.binding.finish();
  }
  return this;
};
AEAD.prototype.setAAD = function (aad) {
  this.binding.setAAD(aad);
  return this;
};
AEAD.prototype._flush = function(next) {
  if (this._decrypt && !this.tag) {
    return this.emit('error', new Error('invalid state'));
  }
  try {
    if (this._decrypt) {
      this.binding.finish(this._tag);
      this._tag = void 0;
    } else {
      this._tag = this.binding.finish();
    }
  } catch(e) {
    this.emit('error', e);
  }
  next();
};

AEAD.prototype.getAuthTag = function () {
  if (!this._tag || this._decrypt) {
    throw new Error('invalid state');
  }
  return this._tag;
};

AEAD.prototype.setAuthTag = function (tag) {
  if (this._tag || !this._decrypt) {
    throw new Error('invalid state');
  }
  this._tag = tag;
  return this;
};
