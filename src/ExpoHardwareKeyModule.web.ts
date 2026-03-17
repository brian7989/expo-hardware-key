import { registerWebModule, NativeModule } from 'expo';

import { ExpoHardwareKeyModuleEvents } from './ExpoHardwareKey.types';

class ExpoHardwareKeyModule extends NativeModule<ExpoHardwareKeyModuleEvents> {
  PI = Math.PI;
  async setValueAsync(value: string): Promise<void> {
    this.emit('onChange', { value });
  }
  hello() {
    return 'Hello world! 👋';
  }
}

export default registerWebModule(ExpoHardwareKeyModule, 'ExpoHardwareKeyModule');
