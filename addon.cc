#include <nan.h>
#include "chacha.h"

using namespace v8;

void InitAll(Handle<Object> exports, Handle<Object> module) {
  Chacha::Init(module);
}

NODE_MODULE(addon, InitAll)
