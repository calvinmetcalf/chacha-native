#include <nan.h>
#include "chacha.h"
#include "poly.h"
#include "aead.h"
#include "chacha2.h"
using namespace v8;

void InitAll(Handle<Object> exports) {
  Chacha::Init(exports);
  Chacha2::Init(exports);
  Poly::Init(exports);
  AEAD::Init(exports);
}

NODE_MODULE(addon, InitAll)
