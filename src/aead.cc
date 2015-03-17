#include <string.h>
#include "aead.h"

using namespace v8;
using namespace node;
Persistent<Function> AEAD::constructor;

AEAD::AEAD() {};
AEAD::~AEAD() {};
void AEAD::Init(Handle<Object> exports) {
  NanScope();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
  tpl->SetClassName(NanNew("AEAD"));
  tpl->InstanceTemplate()->SetInternalFieldCount(5);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "update", Update);
  NODE_SET_PROTOTYPE_METHOD(tpl, "setAAD", UpdateAad);
  NODE_SET_PROTOTYPE_METHOD(tpl, "finish", Finish);

  NanAssignPersistent(constructor, tpl->GetFunction());
  exports->Set(NanNew("AEAD"), tpl->GetFunction());
}

NAN_METHOD(AEAD::New) {
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
    unsigned long long alen = 0;
    AEAD* obj = new AEAD();
    obj->ctx_ = ctx;
    obj->decrypt_ = decrypt;
    obj->clen_ = clen;
    obj->alen_ = alen;
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
NAN_METHOD(AEAD::UpdateAad) {
  NanScope();

  AEAD* obj = ObjectWrap::Unwrap<AEAD>(args.Holder());
  if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0]) ) {
      return NanThrowError("must supply buffer");
    }
    unsigned long long clen = obj->clen_;
    unsigned long long alen = obj->alen_;
    if (clen != 0 || alen != 0) {
      return NanThrowError("invalid state");
    }
    unsigned char* aad = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    size_t aadlen = Buffer::Length(args[0]);
    poly1305_update(&obj->poly_, aad, aadlen);
    unsigned long long longaadlen = (unsigned long long) aadlen;
    obj->alen_ += longaadlen;
    if (aadlen % 16) {
      size_t padding_len = 16 - (aadlen % 16);
      unsigned char* padding = new unsigned char[15];
      memset(padding, 0, 15);
      poly1305_update(&obj->poly_, padding, padding_len);
    }
    NanReturnValue(args.This());
}
NAN_METHOD(AEAD::Update) {
  NanScope();

  AEAD* obj = ObjectWrap::Unwrap<AEAD>(args.Holder());
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

NAN_METHOD(AEAD::Finish) {
  NanScope();

  AEAD* obj = ObjectWrap::Unwrap<AEAD>(args.Holder());
  unsigned long long clen = obj->clen_;
  unsigned long long alen = obj->alen_;
  if (clen % 16) {
    size_t padding_len = 16 - (clen % 16);
    unsigned char* padding = new unsigned char[15];
    memset(padding, 0, 15);
    poly1305_update(&obj->poly_, padding, padding_len);
  }
  unsigned char length_bytes[16];
	unsigned i;
  for (i = 0; i < 8; i++) {
		length_bytes[i] = alen;
    alen >>= 8;
    length_bytes[i + 8] = clen;
    clen >>= 8;
	}
  poly1305_update(&obj->poly_, length_bytes, 16);
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
