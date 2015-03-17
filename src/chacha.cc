#include "chacha.h"

using namespace v8;
using namespace node;
Persistent<Function> Chacha::constructor;

Chacha::Chacha() {};
Chacha::~Chacha() {};
void Chacha::Init(Handle<Object> exports) {
  NanScope();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
  tpl->SetClassName(NanNew("Chacha"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "update", Update);

  NanAssignPersistent(constructor, tpl->GetFunction());
  exports->Set(NanNew("Chacha"), tpl->GetFunction());
}

NAN_METHOD(Chacha::New) {
  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() != 2 ||
        !Buffer::HasInstance(args[0]) ||
        !Buffer::HasInstance(args[1])) {
      return NanThrowError("must supply 2 buffers");
    }
    unsigned char* key = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    unsigned char* iv = reinterpret_cast<unsigned char*>(Buffer::Data(args[1]));
    size_t len = Buffer::Length(args[0]);
    size_t ivlen = Buffer::Length(args[1]);
    if (len != 32) {
      return NanThrowError("invalid key length");
    }
    if (ivlen != 12) {
      return NanThrowError("invalid nonce length");
    }
    chacha20_ctx ctx;
    chacha20_setup(&ctx, key, len, iv);
    Chacha* obj = new Chacha();
    obj->ctx_ = ctx;
    obj->Wrap(args.This());
    NanReturnValue(args.This());
  } else {
    const int argc = 2;
    Local<Value> argv[argc] = { args[0], args[1] };
    Local<Function> cons = NanNew<Function>(constructor);
    NanReturnValue(cons->NewInstance(argc, argv));
  }
}

NAN_METHOD(Chacha::Update) {
  NanScope();

  Chacha* obj = ObjectWrap::Unwrap<Chacha>(args.Holder());
  if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0]) ) {
      return NanThrowError("must supply buffer");
    }
  unsigned char* input = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
  size_t len = Buffer::Length(args[0]);
  unsigned char* out = new unsigned char[len];
  if (!chacha20_encrypt(&obj->ctx_, input, out, len)) {
    return NanThrowError("counter exausted");
  };
  Local<Value> res = NanNewBufferHandle(reinterpret_cast<char*>(out), len);
  NanReturnValue(NanNew(res));
}
