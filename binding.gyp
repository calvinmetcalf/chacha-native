{
  "targets": [
    {
      "target_name": "addon",
      "sources": [
        "addon.cc",
        "chacha20_simple.c",
        "chacha.cc",
        "poly.cc",
        "poly1305-donna.c",
        "aead.cc"
        ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
