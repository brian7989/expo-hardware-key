import { NativeModule, requireNativeModule } from 'expo';

import { ExpoHardwareKeyModuleEvents } from './ExpoHardwareKey.types';

declare class ExpoHardwareKeyModule extends NativeModule<ExpoHardwareKeyModuleEvents> {
  PI: number;
  hello(): string;
  setValueAsync(value: string): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoHardwareKeyModule>('ExpoHardwareKey');
