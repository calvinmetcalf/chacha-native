#include "poly.h"
#include "poly1305-donna.h"

using namespace v8;
using namespace node;
Persistent<Function> Poly::constructor;

Poly::Poly() {};
Poly::~Poly() {};
void Poly::Init(Handle<Object> exports) {
  NanScope();

  // Prepare constructor template
  Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
  tpl->SetClassName(NanNew("Poly"));
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(tpl, "update", Update);
  NODE_SET_PROTOTYPE_METHOD(tpl, "finish", Finish);

  NanAssignPersistent(constructor, tpl->GetFunction());
  exports->Set(NanNew("Poly"), tpl->GetFunction());
}

NAN_METHOD(Poly::New) {
  NanScope();

  if (args.IsConstructCall()) {
    if (args.Length() !=  1||
        !Buffer::HasInstance(args[0])) {
      return NanThrowError("invalid arguments");
    }
    unsigned char* key = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
    size_t len = Buffer::Length(args[0]);
    if (len != 32) {
      return NanThrowError("invalid key length");
    }
    poly1305_context ctx;
    poly1305_init(&ctx, key);
    Poly* obj = new Poly();
    obj->ctx_ = ctx;
    obj->Wrap(args.This());
    NanReturnValue(args.This());
  } else {
    const int argc = 1;
    Local<Value> argv[argc] = { args[0] };
    Local<Function> cons = NanNew<Function>(constructor);
    NanReturnValue(cons->NewInstance(argc, argv));
  }
}

NAN_METHOD(Poly::Update) {
  NanScope();

  Poly* obj = ObjectWrap::Unwrap<Poly>(args.Holder());
  if (args.Length() != 1 ||
        !Buffer::HasInstance(args[0]) ) {
      return NanThrowError("must supply buffer");
    }
  unsigned char* input = reinterpret_cast<unsigned char*>(Buffer::Data(args[0]));
  size_t len = Buffer::Length(args[0]);
  poly1305_update(&obj->ctx_, input, len);
  NanReturnValue(args.This());
}

NAN_METHOD(Poly::Finish) {
  NanScope();

  Poly* obj = ObjectWrap::Unwrap<Poly>(args.Holder());
  unsigned char* mac = new unsigned char[16];
  poly1305_finish(&obj->ctx_, mac);
  Local<Value> res = NanNewBufferHandle(reinterpret_cast<char*>(mac), 16);
  NanReturnValue(NanNew(res));
}
