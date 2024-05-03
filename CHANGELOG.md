# Changelog

- 'type' is shifting to optional (default is '_')

- handleStoreRequest() used to fetch salt, iv from actual
  object stored, changing that to now have separate KV entry,
  so that we can have a privacy window

- using type 'T' for token (meta data)

- changed format for '/storeRequest' to be 'id' not 'key'

- using 'id' everywhere now instead of 'name'

- storeData() now always takes 'any' as input; if you want
  to store an ArrayBuffer, that's fine, your usage of this
  won't change, it's only that internally anything you pass
  to it is always packaged as a payload.

- adjusted 'info' endpoint to match channel server
  
