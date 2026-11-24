import { initializeApp, getApps, getApp, type FirebaseApp } from 'firebase/app';
import { getAnalytics, isSupported, logEvent, type Analytics } from 'firebase/analytics';
import { getAI, GoogleAIBackend, type AI } from 'firebase/ai';

// Firebase configuration for ScamShield AI
export const firebaseConfig = {
  apiKey: 'AIzaSyCSSRedNj2I-7H5aS_T7jjloPoAd4goJ9U',
  authDomain: 'scamshield-ai-24ce6.firebaseapp.com',
  projectId: 'scamshield-ai-24ce6',
  storageBucket: 'scamshield-ai-24ce6.firebasestorage.app',
  messagingSenderId: '409785732688',
  appId: '1:409785732688:web:8321f73e606425da510b55',
  measurementId: 'G-C18NL4KC7P',
};

export const firebaseApp: FirebaseApp = getApps().length ? getApp() : initializeApp(firebaseConfig);

// Initialize Firebase AI Logic with the Gemini Developer API backend (GoogleAIBackend)
export const firebaseAI: AI = getAI(firebaseApp, {
  backend: new GoogleAIBackend(),
});

let analyticsInstance: Analytics | null = null;
let analyticsInitPromise: Promise<Analytics | null> | null = null;

export function initFirebaseAnalytics(): Promise<Analytics | null> {
  if (analyticsInitPromise) {
    return analyticsInitPromise;
  }

  analyticsInitPromise = isSupported()
    .then((supported) => {
      if (!supported) return null;
      analyticsInstance = getAnalytics(firebaseApp);
      return analyticsInstance;
    })
    .catch(() => null);

  return analyticsInitPromise;
}

export async function trackScamEvent(
  eventName: string,
  params?: Record<string, string | number | boolean>
): Promise<void> {
  try {
    const analytics = analyticsInstance ?? (await initFirebaseAnalytics());
    if (analytics) {
      logEvent(analytics, eventName, params);
    }
  } catch {
    // Non-blocking analytics failure
  }
}
