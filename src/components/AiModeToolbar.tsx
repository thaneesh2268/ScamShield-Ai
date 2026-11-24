import { Cloud, Cpu, Lock, RefreshCw } from 'lucide-react';
import type { OnDeviceCapability } from '../types/scam';

interface AiModeToolbarProps {
  capability: OnDeviceCapability;
  checkingCapability: boolean;
  forceCloud: boolean;
  onToggleForceCloud: (next: boolean) => void;
  onRecheckCapability: () => void;
}

export function AiModeToolbar({
  capability,
  checkingCapability,
  forceCloud,
  onToggleForceCloud,
  onRecheckCapability,
}: AiModeToolbarProps) {
  const isRunningOnDevice = !forceCloud && capability.availability !== 'unavailable';

  return (
    <section
      aria-label="Hybrid AI Execution Mode"
      className="rounded-xl border border-slate-200 bg-white p-4 sm:px-5 sm:py-4 dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-4">
          {/* Active AI Mode Status Badge */}
          <div
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-semibold whitespace-nowrap shrink-0 ${
              isRunningOnDevice
                ? 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-800/80 dark:bg-emerald-950/60 dark:text-emerald-200'
                : 'border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-800/80 dark:bg-blue-950/60 dark:text-blue-200'
            }`}
          >
            {isRunningOnDevice ? (
              <Lock className="h-3.5 w-3.5 text-emerald-700 dark:text-emerald-400 shrink-0" aria-hidden="true" />
            ) : (
              <Cloud className="h-3.5 w-3.5 text-blue-700 dark:text-blue-400 shrink-0" aria-hidden="true" />
            )}
            <span>
              {isRunningOnDevice
                ? 'On-Device (Local & Private)'
                : 'Cloud Fallback (Firebase AI Logic)'}
            </span>
          </div>

          {/* Unboxed capability metadata */}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
            <span className="inline-flex items-center gap-1.5 font-medium text-slate-800 dark:text-slate-200">
              <Cpu className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 shrink-0" aria-hidden="true" />
              {capability.availability === 'available'
                ? 'Chrome Built-in AI ready'
                : capability.availability === 'downloadable'
                ? 'Chrome Built-in AI downloadable'
                : 'Chrome Built-in AI unavailable'}
            </span>
            <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
              ·
            </span>
            <span className="text-slate-600 dark:text-slate-400">{capability.detail}</span>
            <button
              type="button"
              onClick={onRecheckCapability}
              disabled={checkingCapability}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 hover:underline underline-offset-2 disabled:opacity-50 cursor-pointer whitespace-nowrap shrink-0"
              title="Re-check window.ai / LanguageModel availability"
            >
              <RefreshCw
                className={`h-3 w-3 ${checkingCapability ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              Re-check
            </button>
          </div>
        </div>

        {/* Manual Toggle Switch for Live Demos */}
        <div className="flex items-center justify-between gap-3 border-t border-slate-100 pt-3 lg:border-t-0 lg:pt-0 dark:border-slate-800 shrink-0">
          <div className="text-left lg:text-right">
            <label
              htmlFor="deep-cloud-toggle"
              className="block text-xs font-semibold text-slate-900 dark:text-slate-100 cursor-pointer whitespace-nowrap"
            >
              Deep Cloud Analysis
            </label>
            <span className="block text-[11px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
              {forceCloud
                ? 'Forcing Firebase AI Logic (Gemini)'
                : 'Prefer on-device when supported'}
            </span>
          </div>

          <button
            id="deep-cloud-toggle"
            type="button"
            role="switch"
            aria-checked={forceCloud}
            onClick={() => onToggleForceCloud(!forceCloud)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 ${
              forceCloud
                ? 'border-blue-600 bg-blue-600'
                : 'border-slate-300 bg-slate-200 dark:border-slate-700 dark:bg-slate-700'
            }`}
          >
            <span className="sr-only">Toggle Deep Cloud Analysis</span>
            <span
              aria-hidden="true"
              className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform duration-150 ${
                forceCloud ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>
    </section>
  );
}
