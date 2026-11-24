import { useMemo, useRef, useState, type ChangeEvent, type RefObject } from 'react';
import { Eraser, ImagePlus, Link2, Loader2, QrCode, SearchCheck, X } from 'lucide-react';
import { SAMPLE_MESSAGES, SOURCE_CONTEXT_OPTIONS } from '../data/samples';
import type {
  ChannelType,
  SampleMessage,
  SourceContext,
  UploadedEvidenceImage,
} from '../types/scam';
import { processUploadedImage } from '../utils/qrDecoder';
import { extractTechnicalSignals } from '../utils/urlInspector';

interface AnalyzerPanelProps {
  input: string;
  channel: ChannelType;
  sourceContext: SourceContext;
  uploadedImage: UploadedEvidenceImage | null;
  isAnalyzing: boolean;
  textareaRef: RefObject<HTMLTextAreaElement | null>;
  onInputChange: (value: string) => void;
  onChannelChange: (channel: ChannelType) => void;
  onSourceContextChange: (context: SourceContext) => void;
  onImageChange: (image: UploadedEvidenceImage | null) => void;
  onAnalyze: (override?: {
    text?: string;
    channel?: ChannelType;
    sourceContext?: SourceContext;
  }) => void;
  onClear: () => void;
}

const CHANNEL_OPTIONS: Array<{ id: ChannelType; label: string }> = [
  { id: 'auto', label: 'Auto' },
  { id: 'sms', label: 'SMS' },
  { id: 'whatsapp', label: 'WhatsApp' },
  { id: 'email', label: 'Email' },
  { id: 'link', label: 'Link / URL' },
];

const MAX_CHARS = 2000;

export function AnalyzerPanel({
  input,
  channel,
  sourceContext,
  uploadedImage,
  isAnalyzing,
  textareaRef,
  onInputChange,
  onChannelChange,
  onSourceContextChange,
  onImageChange,
  onAnalyze,
  onClear,
}: AnalyzerPanelProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [imageError, setImageError] = useState<string | null>(null);
  const [processingImage, setProcessingImage] = useState(false);

  const localSignals = useMemo(() => {
    if (!input.trim() && !uploadedImage?.decodedQrText) return [];
    return extractTechnicalSignals(input, uploadedImage?.decodedQrText);
  }, [input, uploadedImage]);

  const handleSampleClick = (sample: SampleMessage) => {
    const nextText = sample.content.slice(0, MAX_CHARS);
    setImageError(null);
    onImageChange(null);
    onInputChange(nextText);
    onChannelChange(sample.channel);
    onSourceContextChange(sample.sourceContext);
    onAnalyze({
      text: nextText,
      channel: sample.channel,
      sourceContext: sample.sourceContext,
    });
  };

  const handleFileSelected = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    setImageError(null);
    setProcessingImage(true);
    try {
      const processed = await processUploadedImage(file);
      onImageChange(processed);
    } catch (err) {
      setImageError(
        err instanceof Error ? err.message : 'Unable to process uploaded image.'
      );
    } finally {
      setProcessingImage(false);
    }
  };

  const canSubmit = (Boolean(input.trim()) || Boolean(uploadedImage)) && !isAnalyzing && !processingImage;

  return (
    <div className="flex h-full flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-900">
              Message & Link Analyzer
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">
              Paste an SMS, WhatsApp forward, email body, or suspicious URL.
            </p>
          </div>

          {/* Channel Segmented Filter */}
          <div
            role="tablist"
            aria-label="Message channel context"
            className="flex items-center gap-1 rounded-lg bg-slate-100 p-1"
          >
            {CHANNEL_OPTIONS.map((option) => {
              const active = channel === option.id;
              return (
                <button
                  key={option.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => onChannelChange(option.id)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    active
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Input Box */}
        <div className="mt-4">
          <label htmlFor="scam-message-input" className="sr-only">
            Message or link to analyze
          </label>
          <textarea
            ref={textareaRef}
            id="scam-message-input"
            rows={6}
            maxLength={MAX_CHARS}
            value={input}
            onChange={(e) => onInputChange(e.target.value.slice(0, MAX_CHARS))}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && canSubmit) {
                e.preventDefault();
                onAnalyze();
              }
            }}
            placeholder="Example: URGENT: Your bank KYC has expired. Verify immediately at http://..."
            className="w-full resize-y rounded-lg border border-slate-200 bg-slate-50/70 p-3.5 text-sm leading-relaxed text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600/15"
          />

          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
            <div className="flex items-center gap-2 font-mono tabular-nums">
              <span
                className={
                  input.length >= MAX_CHARS
                    ? 'font-semibold text-red-600'
                    : input.length >= 1800
                    ? 'font-medium text-amber-700'
                    : ''
                }
              >
                {input.length} / {MAX_CHARS} chars
              </span>
              {localSignals.length > 0 && (
                <>
                  <span aria-hidden="true" className="text-slate-300">
                    ·
                  </span>
                  <span className="inline-flex items-center gap-1 font-sans font-medium text-slate-700">
                    <Link2 className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
                    {localSignals.length} technical signal{localSignals.length === 1 ? '' : 's'} detected
                  </span>
                </>
              )}
            </div>

            {(input.length > 0 || uploadedImage) && (
              <button
                type="button"
                onClick={() => {
                  setImageError(null);
                  onClear();
                }}
                disabled={isAnalyzing}
                className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900 disabled:opacity-50 cursor-pointer whitespace-nowrap shrink-0"
              >
                <Eraser className="h-3.5 w-3.5" aria-hidden="true" />
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Context Inputs: Source Context Dropdown & Optional Screenshot / QR Upload */}
        <div className="mt-4 grid grid-cols-1 gap-3 border-t border-slate-100 pt-4 sm:grid-cols-2">
          <div>
            <label
              htmlFor="source-context-select"
              className="block text-xs font-medium text-slate-700"
            >
              Source Context
            </label>
            <select
              id="source-context-select"
              value={sourceContext}
              disabled={isAnalyzing}
              onChange={(e) => onSourceContextChange(e.target.value as SourceContext)}
              className="mt-1.5 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-800 focus:border-blue-600 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-600/15 disabled:opacity-50"
            >
              {SOURCE_CONTEXT_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <span className="block text-xs font-medium text-slate-700">
              Evidence Image <span className="font-normal text-slate-500">(Optional)</span>
            </span>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              aria-label="Upload Chat Screenshot or QR"
              onChange={(e) => void handleFileSelected(e)}
              className="sr-only"
            />
            <button
              type="button"
              disabled={isAnalyzing || processingImage}
              onClick={() => fileInputRef.current?.click()}
              className="mt-1.5 flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-700 transition-colors hover:border-slate-400 hover:bg-slate-100 disabled:opacity-50 cursor-pointer whitespace-nowrap"
            >
              {processingImage ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-slate-500" aria-hidden="true" />
                  Scanning image...
                </>
              ) : (
                <>
                  <ImagePlus className="h-3.5 w-3.5 text-slate-600 shrink-0" aria-hidden="true" />
                  Upload Chat Screenshot / QR
                </>
              )}
            </button>
          </div>
        </div>

        {imageError && (
          <p role="alert" className="mt-2 text-xs font-medium text-red-700">
            {imageError}
          </p>
        )}

        {uploadedImage && (
          <div className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-2.5">
            <div className="flex min-w-0 items-center gap-3">
              <img
                src={uploadedImage.previewUrl}
                alt={`Uploaded evidence ${uploadedImage.name}`}
                referrerPolicy="no-referrer"
                className="h-11 w-11 shrink-0 rounded-md border border-slate-200 object-cover bg-white"
              />
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-slate-900">
                  {uploadedImage.name}
                </p>
                {uploadedImage.decodedQrText ? (
                  <p className="mt-0.5 flex items-center gap-1 truncate font-mono text-[11px] text-emerald-700">
                    <QrCode className="h-3 w-3 shrink-0" aria-hidden="true" />
                    QR decoded: {uploadedImage.decodedQrText}
                  </p>
                ) : (
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Ready for Gemini multimodal header & QR inspection
                  </p>
                )}
              </div>
            </div>

            <button
              type="button"
              onClick={() => onImageChange(null)}
              disabled={isAnalyzing}
              aria-label="Remove uploaded screenshot or QR"
              className="rounded-md p-1.5 text-slate-500 hover:bg-slate-200/70 hover:text-slate-900 cursor-pointer shrink-0"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        )}

        {/* One-Click Samples */}
        <div className="mt-4 border-t border-slate-100 pt-4">
          <p className="text-xs font-medium text-slate-600">
            Quick test samples
          </p>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {SAMPLE_MESSAGES.map((sample) => (
              <button
                key={sample.id}
                type="button"
                disabled={isAnalyzing}
                onClick={() => handleSampleClick(sample)}
                title={sample.description}
                className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-800 transition-colors hover:border-slate-300 hover:bg-slate-100 disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Primary Action */}
      <div className="mt-5 flex items-center justify-between gap-4 border-t border-slate-100 pt-4">
        <span className="hidden sm:inline text-xs text-slate-500">
          Press <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">Ctrl</kbd> + <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">Enter</kbd> to scan
        </span>

        <button
          type="button"
          onClick={() => onAnalyze()}
          disabled={!canSubmit}
          className="ml-auto inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              Analyzing...
            </>
          ) : (
            <>
              <SearchCheck className="h-4 w-4" aria-hidden="true" />
              Analyze Message
            </>
          )}
        </button>
      </div>
    </div>
  );
}
