import * as React from 'react';

import { ExpoHardwareKeyViewProps } from './ExpoHardwareKey.types';

export default function ExpoHardwareKeyView(props: ExpoHardwareKeyViewProps) {
  return (
    <div>
      <iframe
        style={{ flex: 1 }}
        src={props.url}
        onLoad={() => props.onLoad({ nativeEvent: { url: props.url } })}
      />
    </div>
  );
}
