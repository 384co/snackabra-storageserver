# Changelog

- 'type' is shifting to optional (default is '_')

- handleStoreRequest() used to fetch salt, iv from actual
  object stored, changing that to now have separate KV entry,
  so that we can have a privacy window

- using type 'T' for token (meta data)

