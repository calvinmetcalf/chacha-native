{
  "targets": [
    {
      "target_name": "chacha20poly1305",
      "sources": [
        "src/chacha20poly1305.cc",
        "src/chacha20_complex.cc",
        "src/chacha.cc",
        "src/chacha2.cc",
        "src/poly.cc",
        "src/poly1305-donna.cc",
        "src/aead.cc"
        ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
         "<(module_root_dir)/deps/gsimd"
      ],
   
    'conditions': [
          ['OS=="linux"', {
            'cflags!': [
              '-Wignored-qualifiers',
            ],
          }]
       ]
    } 
  ]
}
