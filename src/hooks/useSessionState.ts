import { useEffect, useState } from 'react';

import { getSession, subscribe } from '../lib/session';
import type { DemoSessionState } from '../lib/types';

export function useSessionState(): DemoSessionState | null {
  const [state, setState] = useState<DemoSessionState | null>(() => getSession());
  useEffect(() => {
    const unsubscribe = subscribe(() => setState(getSession()));
    return unsubscribe;
  }, []);
  return state;
}
