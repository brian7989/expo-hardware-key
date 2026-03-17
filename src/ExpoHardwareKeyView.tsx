import { requireNativeView } from 'expo';
import * as React from 'react';

import { ExpoHardwareKeyViewProps } from './ExpoHardwareKey.types';

const NativeView: React.ComponentType<ExpoHardwareKeyViewProps> =
  requireNativeView('ExpoHardwareKey');

export default function ExpoHardwareKeyView(props: ExpoHardwareKeyViewProps) {
  return <NativeView {...props} />;
}
