// this section has some type definitions that helps us with CF types
export type EnvType = {
  VERSION: string,
  channels: DurableObjectNamespace, // channel server api
  notifications: Fetcher
  LEDGER_NAMESPACE: KVNamespace,
  IMAGES_NAMESPACE: KVNamespace,
  STORAGE_SERVER: string,
  DEBUG_LEVEL_1: boolean,
  VERBOSE_ON: boolean,
  LOG_ERRORS: boolean,
  ENVIRONMENT?: string,
  PRIVACY_WINDOW?: number,
  IS_LOCAL: boolean, // set to true by 'yarn start' to signal we're on local dev
}
