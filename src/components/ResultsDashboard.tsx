import { useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { getSourceContextLabel } from '../data/samples';
import type { RiskLevel, ScamAnalysisResult } from '../types/scam';

interface ResultsDashboardProps {
  result: ScamAnalysisResult | null;
  isAnalyzing: boolean;
  error: string | null;
  expectedEngineLabel: string;
  onRetry: () => void;
}

const RISK_STYLES: Record<
  RiskLevel,
  {
    banner: string;
    bar: string;
    labelText: string;
    scoreText: string;
    Icon: typeof ShieldCheck;
  }
> = {
  Safe: {
    banner:
      'border-emerald-200 bg-emerald-50/80 text-emerald-950 dark:border-emerald-800/80 dark:bg-emerald-950/50 dark:text-emerald-100',
    bar: 'bg-emerald-600 dark:bg-emerald-500',
    labelText: 'text-emerald-800 dark:text-emerald-400',
    scoreText: 'text-emerald-900 dark:text-emerald-300',
    Icon: ShieldCheck,
  },
  Suspicious: {
    banner:
      'border-amber-200 bg-amber-50/80 text-amber-950 dark:border-amber-800/80 dark:bg-amber-950/50 dark:text-amber-100',
    bar: 'bg-amber-600 dark:bg-amber-500',
    labelText: 'text-amber-800 dark:text-amber-400',
    scoreText: 'text-amber-900 dark:text-amber-300',
    Icon: AlertTriangle,
  },
  'High Risk': {
    banner:
      'border-red-200 bg-red-50/80 text-red-950 dark:border-red-800/80 dark:bg-red-950/50 dark:text-red-100',
    bar: 'bg-red-600 dark:bg-red-500',
    labelText: 'text-red-800 dark:text-red-400',
    scoreText: 'text-red-900 dark:text-red-300',
    Icon: ShieldAlert,
  },
};

export function ResultsDashboard({
  result,
  isAnalyzing,
  error,
  expectedEngineLabel,
  onRetry,
}: ResultsDashboardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopyReport = async () => {
    if (!result) return;
    const report = [
      `ScamShield AI Verdict: ${result.riskLevel} (${result.confidenceScore}% confidence)`,
      `Channel: ${result.detectedChannel}`,
      `Source Context: ${getSourceContextLabel(result.sourceContext)}`,
      `Engine: ${result.engine === 'on-device' ? 'On-Device (Chrome Built-in AI)' : 'Cloud Fallback (Firebase AI Logic)'}`,
      `Summary: ${result.summary}`,
      '',
      `Sender Mismatch: ${result.technicalBreakdown.senderMismatch.status} - ${result.technicalBreakdown.senderMismatch.detail}`,
      `Payment Trigger: ${result.technicalBreakdown.paymentTriggerType.category} - ${result.technicalBreakdown.paymentTriggerType.detail}`,
      '',
      `${result.riskLevel === 'Safe' ? 'Trust Signals' : 'Red Flags'}:`,
      ...result.redFlags.map((flag) => `- ${flag}`),
      '',
      'Recommended Safe Actions:',
      ...result.safeActions.map((action, idx) => `${idx + 1}. ${action}`),
    ].join('\n');

    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard fallback ignored if blocked
    }
  };

  if (isAnalyzing) {
    return (
      <div
        aria-live="polite"
        aria-busy="true"
        className="flex h-full flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900"
      >
        <div>
          <div className="flex items-center justify-between gap-4 border-b border-slate-100 pb-4 dark:border-slate-800">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Running Threat Analysis
              </p>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                Routing via {expectedEngineLabel}
              </p>
            </div>
            <span className="font-mono text-xs text-slate-500 dark:text-slate-400 tabular-nums">
              Inspecting...
            </span>
          </div>

          <div className="mt-5 animate-pulse space-y-5">
            <div className="h-24 rounded-lg bg-slate-100 dark:bg-slate-800" />
            <div className="space-y-2">
              <div className="h-3.5 w-32 rounded bg-slate-100 dark:bg-slate-800" />
              <div className="h-4 w-full rounded bg-slate-100 dark:bg-slate-800" />
              <div className="h-4 w-5/6 rounded bg-slate-100 dark:bg-slate-800" />
            </div>
            <div className="space-y-2 pt-2">
              <div className="h-3.5 w-44 rounded bg-slate-100 dark:bg-slate-800" />
              <div className="h-16 w-full rounded bg-slate-100 dark:bg-slate-800" />
            </div>
            <div className="space-y-2 pt-2">
              <div className="h-3.5 w-40 rounded bg-slate-100 dark:bg-slate-800" />
              <div className="h-3.5 w-5/6 rounded bg-slate-100 dark:bg-slate-800" />
              <div className="h-3.5 w-2/3 rounded bg-slate-100 dark:bg-slate-800" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className="flex h-full flex-col justify-between rounded-xl border border-red-200 bg-white p-5 sm:p-6 dark:border-red-900/70 dark:bg-slate-900"
      >
        <div>
          <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-red-950 dark:border-red-800/80 dark:bg-red-950/50 dark:text-red-100">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-700 dark:text-red-400" aria-hidden="true" />
            <div>
              <h3 className="text-sm font-semibold">Analysis could not complete</h3>
              <p className="mt-1 text-sm leading-relaxed text-red-800 dark:text-red-200">{error}</p>
            </div>
          </div>
        </div>

        <div className="mt-6 border-t border-slate-100 pt-4 dark:border-slate-800">
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white cursor-pointer whitespace-nowrap"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
            Retry Analysis
          </button>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex h-full flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Results Dashboard
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            Select a sample message, paste text, or upload a chat screenshot / QR image to inspect it.
          </p>

          <dl className="mt-6 divide-y divide-slate-100 border-t border-slate-100 dark:divide-slate-800 dark:border-slate-800">
            <div className="py-3.5">
              <dt className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                01. Extracted URL Parts & QR Payloads
              </dt>
              <dd className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                Deconstructs protocol, domain host, TLD, query parameters, and embedded UPI QR strings.
              </dd>
            </div>
            <div className="py-3.5">
              <dt className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                02. Sender Header & Country Code Mismatch
              </dt>
              <dd className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                Cross-checks Source Context and visible screenshot sender headers against claimed banks or couriers.
              </dd>
            </div>
            <div className="py-3.5">
              <dt className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                03. Payment Trigger & Hybrid AI Reasoning
              </dt>
              <dd className="mt-1 text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                Identifies UPI PIN traps or credential phishing using Chrome Built-in AI or Firebase AI Logic.
              </dd>
            </div>
          </dl>
        </div>

        <p className="mt-6 border-t border-slate-100 pt-4 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          Every verdict includes a confidence score, technical breakdown, red flags, and safe next steps.
        </p>
      </div>
    );
  }

  const style = RISK_STYLES[result.riskLevel];
  const RiskIcon = style.Icon;
  const isSafe = result.riskLevel === 'Safe';
  const { urlParts, senderMismatch, paymentTriggerType } = result.technicalBreakdown;

  const mismatchTone =
    senderMismatch.status === 'Mismatch Detected'
      ? 'text-red-700 dark:text-red-400'
      : senderMismatch.status === 'Potential Mismatch'
      ? 'text-amber-700 dark:text-amber-400'
      : senderMismatch.status === 'Consistent'
      ? 'text-emerald-700 dark:text-emerald-400'
      : 'text-slate-700 dark:text-slate-300';

  return (
    <div
      aria-live="polite"
      className="flex h-full flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 sm:p-6 dark:border-slate-800 dark:bg-slate-900"
    >
      <div>
        {/* Verdict Banner */}
        <div className={`rounded-lg border p-4 ${style.banner}`}>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <RiskIcon className={`mt-0.5 h-6 w-6 shrink-0 ${style.labelText}`} aria-hidden="true" />
              <div>
                <p className="text-xs font-medium opacity-80">Threat Verdict</p>
                <h2 className="text-xl font-bold tracking-tight">
                  {result.riskLevel}
                </h2>
              </div>
            </div>

            <div className="text-right">
              <p className="text-xs font-medium opacity-80">Confidence Score</p>
              <p className={`font-mono text-2xl font-bold tabular-nums ${style.scoreText}`}>
                {result.confidenceScore}%
              </p>
            </div>
          </div>

          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-black/10 dark:bg-white/10">
            <div
              className={`h-full rounded-full transition-all duration-300 ${style.bar}`}
              style={{ width: `${result.confidenceScore}%` }}
            />
          </div>
        </div>

        {/* Unboxed Execution Metadata */}
        <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
          <span className="font-semibold text-slate-900 dark:text-slate-100">
            {result.engine === 'on-device'
              ? 'On-Device (Local & Private)'
              : 'Cloud Fallback (Firebase AI Logic)'}
          </span>
          <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
            ·
          </span>
          <span>{result.detectedChannel}</span>
          {result.sourceContext !== 'unspecified' && (
            <>
              <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
                ·
              </span>
              <span>{getSourceContextLabel(result.sourceContext)}</span>
            </>
          )}
          <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
            ·
          </span>
          <span className="font-mono tabular-nums">{result.latencyMs} ms</span>
          <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
            ·
          </span>
          <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
            {result.modelName}
          </span>
        </div>

        {/* Executive Summary */}
        <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
          <p className="text-sm leading-relaxed text-slate-800 dark:text-slate-200">
            {result.summary}
          </p>
        </div>

        {/* Technical Signal Breakdown Card */}
        <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
          <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
            Technical Signal Breakdown
          </h3>

          <dl className="mt-2.5 divide-y divide-slate-200/80 rounded-lg border border-slate-200 bg-slate-50/70 dark:divide-slate-800 dark:border-slate-800 dark:bg-slate-950/60">
            {/* 1. Extracted URL Parts */}
            <div className="p-3">
              <dt className="text-[11px] font-semibold text-slate-700 dark:text-slate-300">
                Extracted URL Parts
              </dt>
              <dd className="mt-1.5">
                {urlParts.length === 0 ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    No HTTP/HTTPS or UPI URLs extracted from text or QR payload.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {urlParts.map((part, idx) => (
                      <div key={idx} className="space-y-1 text-xs">
                        <div className="grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[11px] sm:grid-cols-4">
                          <div>
                            <span className="block font-sans text-[10px] text-slate-500 dark:text-slate-400">Protocol</span>
                            <span className="font-medium text-slate-900 dark:text-slate-100">{part.protocol}</span>
                          </div>
                          <div className="col-span-2 sm:col-span-1">
                            <span className="block font-sans text-[10px] text-slate-500 dark:text-slate-400">Host / Payee</span>
                            <span className="block truncate font-medium text-slate-900 dark:text-slate-100" title={part.host}>
                              {part.host}
                            </span>
                          </div>
                          <div>
                            <span className="block font-sans text-[10px] text-slate-500 dark:text-slate-400">TLD / Handle</span>
                            <span className="font-medium text-slate-900 dark:text-slate-100">{part.tld}</span>
                          </div>
                          <div>
                            <span className="block font-sans text-[10px] text-slate-500 dark:text-slate-400">Path / Query</span>
                            <span className="block truncate text-slate-700 dark:text-slate-300" title={part.path}>
                              {part.path}
                            </span>
                          </div>
                        </div>
                        <p
                          className={`text-[11px] font-medium ${
                            part.severity === 'danger'
                              ? 'text-red-700 dark:text-red-400'
                              : part.severity === 'warning'
                              ? 'text-amber-700 dark:text-amber-400'
                              : 'text-emerald-700 dark:text-emerald-400'
                          }`}
                        >
                          {part.flags.join(' · ')}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </dd>
            </div>

            {/* 2. Sender Mismatch */}
            <div className="p-3">
              <dt className="flex items-center justify-between gap-2 text-[11px] font-semibold text-slate-700 dark:text-slate-300">
                <span>Sender Mismatch</span>
                <span className={`font-semibold ${mismatchTone}`}>
                  {senderMismatch.status}
                </span>
              </dt>
              <dd className="mt-1 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                {senderMismatch.detail}
              </dd>
            </div>

            {/* 3. Payment Trigger Type */}
            <div className="p-3">
              <dt className="flex items-center justify-between gap-2 text-[11px] font-semibold text-slate-700 dark:text-slate-300">
                <span>Payment Trigger Type</span>
                <span
                  className={`font-semibold ${
                    paymentTriggerType.isHighRisk
                      ? 'text-red-700 dark:text-red-400'
                      : 'text-slate-700 dark:text-slate-300'
                  }`}
                >
                  {paymentTriggerType.category}
                </span>
              </dt>
              <dd className="mt-1 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                {paymentTriggerType.detail}
              </dd>
            </div>
          </dl>
        </div>

        {/* Bulleted Red Flags / Trust Signals */}
        <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
          <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
            {isSafe ? 'Verified Trust Signals' : 'Red Flags Detected'}
          </h3>
          <ul className="mt-2 list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            {result.redFlags.map((flag, index) => (
              <li key={index}>{flag}</li>
            ))}
          </ul>
        </div>

        {/* Recommended Safe Actions */}
        <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
          <h3 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
            Recommended Safe Actions
          </h3>
          <ul className="mt-2 space-y-1.5 text-sm leading-relaxed text-slate-700 dark:text-slate-300">
            {result.safeActions.map((action, index) => (
              <li key={index} className="flex items-start gap-2">
                <CheckCircle2
                  className="mt-0.5 h-4 w-4 shrink-0 text-blue-600 dark:text-blue-400"
                  aria-hidden="true"
                />
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Footer Actions */}
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4 dark:border-slate-800">
        <span className="text-xs text-slate-500 dark:text-slate-400">{result.engineDetail}</span>

        <button
          type="button"
          onClick={handleCopyReport}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 cursor-pointer whitespace-nowrap shrink-0"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
              Copied Report
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" aria-hidden="true" />
              Copy Report
            </>
          )}
        </button>
      </div>
    </div>
  );
}
