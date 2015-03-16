{
  "targets": [
    {
      "target_name": "chacha",
      "sources": [
        "src/binding.cc",
        "src/chacha20_simple.cc",
        "src/chacha.cc",
        "src/poly.cc",
        "src/poly1305-donna.cc",
        "src/aead.cc"
        ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
