// this section has some type definitions that helps us with CF types
export type EnvType = {
  VERSION: string,
  channels: DurableObjectNamespace, // channel server api
  notifications: Fetcher
  LEDGER_NAMESPACE: KVNamespace,
  IMAGES_NAMESPACE: KVNamespace,
  STORAGE_SERVER: string,
  DEBUG_ON: boolean,
  VERBOSE_ON: boolean,
  LOG_ERRORS: boolean,
  ENVIRONMENT?: string,
  PRIVACY_WINDOW?: number,
}
