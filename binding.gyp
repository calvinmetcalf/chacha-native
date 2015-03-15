{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "addon.cc", "chacha20_simple.c", "chacha.cc"],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
