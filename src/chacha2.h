#ifndef CHACHA2_H
#define CHACHA2_H

#include <nan.h>
#include "chacha20_simple.h"

class Chacha2 : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);

 private:
  Chacha2();
  ~Chacha2();

  static NAN_METHOD(New);
  static NAN_METHOD(Update);
  static v8::Persistent<v8::Function> constructor;
  chacha20_ctx ctx_;
};

#endif
