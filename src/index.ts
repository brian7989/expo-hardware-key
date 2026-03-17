// Reexport the native module. On web, it will be resolved to ExpoHardwareKeyModule.web.ts
// and on native platforms to ExpoHardwareKeyModule.ts
export { default } from './ExpoHardwareKeyModule';
export { default as ExpoHardwareKeyView } from './ExpoHardwareKeyView';
export * from  './ExpoHardwareKey.types';
