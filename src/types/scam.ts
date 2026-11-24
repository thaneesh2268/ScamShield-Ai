export type ChannelType = 'auto' | 'sms' | 'whatsapp' | 'email' | 'link';

export type SourceContext =
  | 'unspecified'
  | 'unknown-10-digit'
  | 'forwarded-message'
  | 'unverified-account'
  | 'sms';

export type RiskLevel = 'Safe' | 'Suspicious' | 'High Risk';

export type ExecutionEngine = 'on-device' | 'cloud-fallback';

export type OnDeviceAvailability = 'available' | 'downloadable' | 'unavailable';

export type PromptApiKind = 'LanguageModel' | 'window.ai' | 'none';

export interface OnDeviceCapability {
  availability: OnDeviceAvailability;
  apiKind: PromptApiKind;
  detail: string;
}

export interface UploadedEvidenceImage {
  name: string;
  mimeType: string;
  base64Data: string;
  previewUrl: string;
  sizeBytes: number;
  decodedQrText: string | null;
}

export interface ExtractedSignal {
  kind: 'url' | 'upi' | 'phone' | 'email' | 'pattern' | 'qr';
  value: string;
  note: string;
  severity: 'info' | 'warning' | 'danger';
}

export interface ParsedUrlBreakdown {
  raw: string;
  protocol: string;
  host: string;
  tld: string;
  path: string;
  flags: string[];
  severity: 'info' | 'warning' | 'danger';
}

export interface TechnicalSignalBreakdown {
  urlParts: ParsedUrlBreakdown[];
  senderMismatch: {
    status: 'Mismatch Detected' | 'Potential Mismatch' | 'Consistent' | 'Unverified';
    detail: string;
  };
  paymentTriggerType: {
    category: string;
    detail: string;
    isHighRisk: boolean;
  };
}

export interface ScamAnalysisResult {
  id: string;
  timestamp: number;
  input: string;
  channel: ChannelType;
  sourceContext: SourceContext;
  hasImageEvidence: boolean;
  decodedQrText: string | null;
  detectedChannel: string;
  riskLevel: RiskLevel;
  confidenceScore: number;
  summary: string;
  redFlags: string[];
  safeActions: string[];
  extractedSignals: ExtractedSignal[];
  technicalBreakdown: TechnicalSignalBreakdown;
  engine: ExecutionEngine;
  engineDetail: string;
  modelName: string;
  latencyMs: number;
}

export interface SampleMessage {
  id: string;
  label: string;
  channel: ChannelType;
  sourceContext: SourceContext;
  description: string;
  content: string;
}
