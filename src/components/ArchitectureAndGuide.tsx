import { Cloud, Cpu, Lock, ShieldAlert } from 'lucide-react';

export function ArchitectureAndGuide() {
  return (
    <div className="space-y-8">
      {/* Hybrid AI Architecture */}
      <section
        id="architecture"
        className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="max-w-2xl">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Hybrid AI Architecture
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            ScamShield AI prioritizes local privacy with Chrome Built-in AI and guarantees universal reliability through Firebase AI Logic.
          </p>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-6 border-t border-slate-100 pt-5 md:grid-cols-2 dark:border-slate-800">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
              <Cpu className="h-4 w-4 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
              <span>01. On-Device AI First (Chrome Prompt API)</span>
            </div>
            <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
              Checks <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">LanguageModel</code> and{' '}
              <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">window.ai.languageModel</code> availability in the user&apos;s browser. When ready, sensitive personal SMS, WhatsApp forwards, and banking alerts are classified locally on-device with zero network egress and offline resilience.
            </p>
            <div className="flex items-center gap-2 pt-1 text-xs text-slate-500 dark:text-slate-400">
              <Lock className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
              <span>Instant local execution · Private by default · Works offline</span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
              <Cloud className="h-4 w-4 text-blue-700 dark:text-blue-400" aria-hidden="true" />
              <span>02. Cloud AI Fallback (Firebase AI Logic)</span>
            </div>
            <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
              Connects to Firebase using <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">firebase/ai</code>{' '}
              (<code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">getAI</code> +{' '}
              <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">GoogleAIBackend</code> +{' '}
              <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">getGenerativeModel</code>). Users on Safari, Firefox, mobile, or those enabling Deep Cloud Analysis get structured Gemini reasoning across complex phishing campaigns and screenshots.
            </p>
            <div className="flex items-center gap-2 pt-1 text-xs text-slate-500 dark:text-slate-400">
              <span>Cross-browser coverage · Structured JSON Schema · Firebase Analytics telemetry</span>
            </div>
          </div>
        </div>
      </section>

      {/* Threat Guide */}
      <section
        id="guide"
        className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900"
      >
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Common Scam Patterns Detected
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Core social-engineering vectors covered by ScamShield AI&apos;s dual-layer signal inspector.
            </p>
          </div>
          <ShieldAlert className="h-5 w-5 text-slate-400 dark:text-slate-500 shrink-0" aria-hidden="true" />
        </div>

        <div className="mt-5 grid grid-cols-1 gap-6 border-t border-slate-100 pt-5 md:grid-cols-3 dark:border-slate-800">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Fake Bank KYC & Suspension SMS
            </h3>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Threatens immediate account or card blocking within hours unless you tap an unverified lookalike domain (for example <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px] dark:bg-slate-800">.xyz</code> or hyphenated brand clones) to submit PAN, OTP, or login credentials.
            </p>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              UPI Lottery & Cashback Collect Traps
            </h3>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Promises instant prize money or cashback via a <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px] dark:bg-slate-800">upi://pay</code> link or QR code. Entering a UPI PIN always authorizes an outgoing debit—never an incoming reward.
            </p>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Courier & Delivery Spoofing
            </h3>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
              Distinguishes genuine courier alerts linking to official HTTPS tracking portals from phishing lures demanding small redelivery fees or card verification on shortened URLs.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
