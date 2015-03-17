#include <string.h>
#include "legacy.h"

using namespace v8;
using namespace node;
Persistent<Function> Legacy::constructor;

Legacy::Legacy() {};
Legacy::~Legacy() {};
void Legacy::Init(Handle<Object> exports) {
  NanScope();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
  tpl->SetClassName(NanNew("Legacy"));
  tpl->InstanceTemplate()->SetInternalFieldCount(4);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "update", Update);
  NODE_SET_PROTOTYPE_METHOD(tpl, "setAAD", UpdateAad);
  NODE_SET_PROTOTYPE_METHOD(tpl, "finish", Finish);

  NanAssignPersistent(constructor, tpl->GetFunction());
  exports->Set(NanNew("Legacy"), tpl->GetFunction());
}

NAN_METHOD(Legacy::New) {
  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() < 3 ||
        !Buffer::HasInstance(args[0]) ||
        !Buffer::HasInstance(args[1])) {
      return NanThrowError("must supply key and iv");
    }
    unsigned char* key = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    unsigned char* iv = reinterpret_cast<unsigned char*>(Buffer::Data(args[1]));
    bool decrypt = args[3]->IsUndefined() ? false : args[0]->BooleanValue();
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
    unsigned long long clen = 0;
    Legacy* obj = new Legacy();
    obj->ctx_ = ctx;
    obj->decrypt_ = decrypt;
    obj->clen_ = clen;
    poly1305_context poly;

    unsigned char* polykey = new unsigned char[64];
    memset(polykey, 0, 64);
    chacha20_encrypt(&obj->ctx_, polykey, polykey, 64);
    obj->poly_ = poly;
    poly1305_init(&obj->poly_, polykey);
    obj->Wrap(args.This());
    NanReturnValue(args.This());
  } else {
    const int argc = 3;
    Local<Value> argv[argc] = { args[0], args[1], args[2]};
    Local<Function> cons = NanNew<Function>(constructor);
    NanReturnValue(cons->NewInstance(argc, argv));
  }
}
NAN_METHOD(Legacy::UpdateAad) {
  NanScope();

  Legacy* obj = ObjectWrap::Unwrap<Legacy>(args.Holder());
  if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0]) ) {
      return NanThrowError("must supply buffer");
    }
    unsigned long long clen = obj->clen_;
    if (clen != 0) {
      return NanThrowError("invalid state");
    }
    unsigned char* aad = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    size_t aadlen = Buffer::Length(args[0]);
    poly1305_update(&obj->poly_, aad, aadlen);
    unsigned char length_bytes[8];
    unsigned i;
    for (i = 0; i < 8; i++) {
      length_bytes[i] = aadlen;
      aadlen >>= 8;
    }
    poly1305_update(&obj->poly_, length_bytes, 8);
    NanReturnValue(args.This());
}
NAN_METHOD(Legacy::Update) {
  NanScope();

  Legacy* obj = ObjectWrap::Unwrap<Legacy>(args.Holder());
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

  if (obj->decrypt_) {
    poly1305_update(&obj->poly_, input, len);
  } else {
    poly1305_update(&obj->poly_, out, len);
  }
  unsigned long long longlen = (unsigned long long) len;
  obj->clen_ += longlen;
  Local<Value> res = NanNewBufferHandle(reinterpret_cast<char*>(out), len);
  NanReturnValue(NanNew(res));
}

NAN_METHOD(Legacy::Finish) {
  NanScope();

  Legacy* obj = ObjectWrap::Unwrap<Legacy>(args.Holder());
  unsigned long long clen = obj->clen_;
  unsigned char length_bytes[8];
	unsigned i;
  for (i = 0; i < 8; i++) {
    length_bytes[i] = clen;
    clen >>= 8;
	}
  poly1305_update(&obj->poly_, length_bytes, 8);
  unsigned char* mac = new unsigned char[16];
  poly1305_finish(&obj->poly_, mac);
  bool decrypt = obj -> decrypt_;
  if (decrypt) {
    if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0])) {
          return NanThrowError("must supply tag");
        }
    unsigned char* tag = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    if (poly1305_verify(tag, mac) == 1) {
      NanReturnValue(NanUndefined());
    } else {
      return NanThrowError("unable to authenticate");
    }
  } else {
    Local<Value> res = NanNewBufferHandle(reinterpret_cast<char*>(mac), 16);
    NanReturnValue(NanNew(res));
  }
}
