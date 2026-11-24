import { useCallback, useEffect, useRef, useState } from 'react';
import { AiModeToolbar } from './components/AiModeToolbar';
import { AnalyzerPanel } from './components/AnalyzerPanel';
import { ArchitectureAndGuide } from './components/ArchitectureAndGuide';
import { ResultsDashboard } from './components/ResultsDashboard';
import { ScanHistoryTable } from './components/ScanHistoryTable';
import { TopBar } from './components/TopBar';
import { initFirebaseAnalytics, trackScamEvent } from './lib/firebase';
import { analyzeScamMessage, detectOnDeviceCapability } from './services/scamAnalyzer';
import type {
  ChannelType,
  OnDeviceCapability,
  ScamAnalysisResult,
  SourceContext,
  UploadedEvidenceImage,
} from './types/scam';
import { buildLocalTechnicalBreakdown } from './utils/urlInspector';

const HISTORY_STORAGE_KEY = 'scamshield_scan_history_v1';

function loadSavedHistory(): ScamAnalysisResult[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((item: ScamAnalysisResult) => {
      const sourceContext: SourceContext = item.sourceContext ?? 'unspecified';
      const technicalBreakdown =
        item.technicalBreakdown ??
        buildLocalTechnicalBreakdown(item.input ?? '', sourceContext, item.decodedQrText ?? null);
      return {
        ...item,
        sourceContext,
        hasImageEvidence: Boolean(item.hasImageEvidence),
        decodedQrText: item.decodedQrText ?? null,
        technicalBreakdown,
      };
    });
  } catch {
    return [];
  }
}

export default function App() {
  const [input, setInput] = useState('');
  const [channel, setChannel] = useState<ChannelType>('auto');
  const [sourceContext, setSourceContext] = useState<SourceContext>('unspecified');
  const [uploadedImage, setUploadedImage] = useState<UploadedEvidenceImage | null>(null);
  const [forceCloud, setForceCloud] = useState(false);
  const [capability, setCapability] = useState<OnDeviceCapability>({
    availability: 'unavailable',
    apiKind: 'none',
    detail: 'Checking Chrome Built-in AI availability...',
  });
  const [checkingCapability, setCheckingCapability] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentResult, setCurrentResult] = useState<ScamAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ScamAnalysisResult[]>(() => loadSavedHistory());

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const checkCapabilities = useCallback(async () => {
    setCheckingCapability(true);
    const detected = await detectOnDeviceCapability();
    setCapability(detected);
    setCheckingCapability(false);
  }, []);

  useEffect(() => {
    void initFirebaseAnalytics();
    void checkCapabilities();
  }, [checkCapabilities]);

  useEffect(() => {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history.slice(0, 25)));
    } catch {
      // Ignore storage quota errors
    }
  }, [history]);

  const handleToggleForceCloud = (next: boolean) => {
    setForceCloud(next);
    void trackScamEvent('ai_mode_toggled', {
      deep_cloud_enabled: next,
      on_device_available: capability.availability !== 'unavailable',
    });
  };

  const handleAnalyze = async (override?: {
    text?: string;
    channel?: ChannelType;
    sourceContext?: SourceContext;
  }) => {
    const targetText = override?.text !== undefined ? override.text : input;
    const targetChannel = override?.channel !== undefined ? override.channel : channel;
    const targetSourceContext =
      override?.sourceContext !== undefined ? override.sourceContext : sourceContext;
    const targetImage = override?.text !== undefined ? null : uploadedImage;

    if (!targetText.trim() && !targetImage) return;

    setIsAnalyzing(true);
    setError(null);

    try {
      const result = await analyzeScamMessage({
        message: targetText,
        channel: targetChannel,
        sourceContext: targetSourceContext,
        uploadedImage: targetImage,
        forceCloud,
        capability,
      });
      setCurrentResult(result);
      setHistory((prev) => [result, ...prev.filter((item) => item.id !== result.id)].slice(0, 25));
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : 'Unable to complete scam analysis. Please check your connection and try again.';
      setError(message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleNewScan = () => {
    setInput('');
    setChannel('auto');
    setSourceContext('unspecified');
    setUploadedImage(null);
    setCurrentResult(null);
    setError(null);
    const el = document.getElementById('analyzer');
    el?.scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => textareaRef.current?.focus(), 150);
  };

  const handleClear = () => {
    setInput('');
    setUploadedImage(null);
    setCurrentResult(null);
    setError(null);
    textareaRef.current?.focus();
  };

  const handleSelectHistoryScan = (scan: ScamAnalysisResult) => {
    setInput(scan.input);
    setChannel(scan.channel);
    setSourceContext(scan.sourceContext ?? 'unspecified');
    setUploadedImage(null);
    setCurrentResult(scan);
    setError(null);
    document.getElementById('analyzer')?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // Ignore storage error
    }
  };

  const expectedEngineLabel =
    uploadedImage
      ? 'Gemini Multimodal Analysis (Firebase AI Logic)'
      : !forceCloud && capability.availability !== 'unavailable'
      ? 'On-Device Chrome Built-in AI'
      : 'Cloud Fallback (Firebase AI Logic)';

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <TopBar onNewScan={handleNewScan} />

      <main className="mx-auto max-w-[1200px] space-y-8 px-4 py-8 sm:px-6 lg:py-10">
        {/* Hero Header */}
        <section id="analyzer" className="space-y-5">
          <div className="max-w-3xl">
            <p className="text-xs font-medium text-slate-500">
              BuildHybridAI 2026 <span aria-hidden="true">·</span> Chrome Prompt API & Firebase AI Logic
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-900 text-balance sm:text-4xl">
              Hybrid AI scam detection for SMS, WhatsApp, email, and links.
            </h1>
            <p className="mt-2.5 text-base leading-relaxed text-slate-600">
              Inspects suspicious messages on-device first using Chrome Built-in AI for instant offline privacy, with seamless cloud reasoning via Firebase AI Logic on any browser.
            </p>
          </div>

          {/* AI Mode Status Badge & Live Demo Toggle */}
          <AiModeToolbar
            capability={capability}
            checkingCapability={checkingCapability}
            forceCloud={forceCloud}
            onToggleForceCloud={handleToggleForceCloud}
            onRecheckCapability={() => void checkCapabilities()}
          />

          {/* Primary 2-Column Workspace */}
          <div className="grid grid-cols-1 items-stretch gap-6 lg:grid-cols-12">
            <div className="lg:col-span-6">
              <AnalyzerPanel
                input={input}
                channel={channel}
                sourceContext={sourceContext}
                uploadedImage={uploadedImage}
                isAnalyzing={isAnalyzing}
                textareaRef={textareaRef}
                onInputChange={setInput}
                onChannelChange={setChannel}
                onSourceContextChange={setSourceContext}
                onImageChange={setUploadedImage}
                onAnalyze={(override) => void handleAnalyze(override)}
                onClear={handleClear}
              />
            </div>

            <div className="lg:col-span-6">
              <ResultsDashboard
                result={currentResult}
                isAnalyzing={isAnalyzing}
                error={error}
                expectedEngineLabel={expectedEngineLabel}
                onRetry={() => void handleAnalyze()}
              />
            </div>
          </div>
        </section>

        {/* Session Scan History */}
        <ScanHistoryTable
          history={history}
          activeId={currentResult?.id ?? null}
          onSelectScan={handleSelectHistoryScan}
          onClearHistory={handleClearHistory}
        />

        {/* Hybrid AI Architecture & Threat Guide */}
        <ArchitectureAndGuide />
      </main>

      <footer className="mt-12 border-t border-slate-200 bg-white">
        <div className="mx-auto flex max-w-[1200px] flex-col gap-2 px-4 py-6 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <span>ScamShield AI · Built for BuildHybridAI 2026</span>
          <span>On-device Chrome Prompt API with Firebase AI Logic cloud fallback</span>
        </div>
      </footer>
    </div>
  );
}
