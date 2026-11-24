import { getGenerativeModel, Schema, type GenerativeModel, type Part } from 'firebase/ai';
import { getSourceContextLabel } from '../data/samples';
import { firebaseAI, trackScamEvent } from '../lib/firebase';
import type {
  ChannelType,
  ExtractedSignal,
  OnDeviceCapability,
  RiskLevel,
  ScamAnalysisResult,
  SourceContext,
  TechnicalSignalBreakdown,
  UploadedEvidenceImage,
} from '../types/scam';
import {
  buildLocalTechnicalBreakdown,
  extractTechnicalSignals,
} from '../utils/urlInspector';

interface ChromeLanguageModelSession {
  prompt: (input: string) => Promise<string>;
  destroy?: () => void;
  tokensLeft?: number;
}

interface ChromeLanguageModelGlobal {
  availability?: () => Promise<'available' | 'downloadable' | 'downloading' | 'unavailable'>;
  create: (options?: {
    systemPrompt?: string;
    initialPrompts?: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
  }) => Promise<ChromeLanguageModelSession>;
}

interface LegacyWindowAI {
  languageModel?: {
    capabilities: () => Promise<{ available: 'readily' | 'after-download' | 'no' }>;
    create: (options?: { systemPrompt?: string }) => Promise<ChromeLanguageModelSession>;
  };
}

interface RawAIAnalysisPayload {
  riskLevel: RiskLevel;
  confidenceScore: number;
  detectedChannel: string;
  summary: string;
  redFlags: string[];
  safeActions: string[];
  senderMismatchStatus?: 'Mismatch Detected' | 'Potential Mismatch' | 'Consistent' | 'Unverified';
  senderMismatchDetail?: string;
  paymentTriggerCategory?: string;
  paymentTriggerDetail?: string;
  paymentTriggerHighRisk?: boolean;
}

const TEXT_SYSTEM_PROMPT = `ScamShield AI threat classifier. Output ONLY valid JSON:
{"riskLevel":"Safe"|"Suspicious"|"High Risk","confidenceScore":0-100,"detectedChannel":"SMS"|"WhatsApp"|"Email"|"URL / Link"|"QR Payment","summary":"1 short sentence <=15 words","redFlags":["max 3 bullets <=9 words each"],"safeActions":["max 3 bullets <=9 words each"]}
Rules:
- High Risk: KYC/account block threats, abusive/lookalike domains (.xyz/.top/hyphenated banks), UPI lottery/QR asking PIN to receive money, OTP/CVV/credential theft, sender spoofing.
- Suspicious: Shortened links, mild urgency, unsolicited offers, unknown 10-digit requests.
- Safe: Official HTTPS notifications with no PIN/credential/payment traps (doorstep delivery OTP is safe). If Safe, redFlags holds 2-3 brief trust signals.`;

const VISION_SYSTEM_PROMPT = `ScamShield AI multimodal fraud analyst. Inspect message, Source Context, and screenshot/QR (sender header, country codes, unverified badges, UPI QR payee/amount). Output ONLY valid JSON:
{"riskLevel":"Safe"|"Suspicious"|"High Risk","confidenceScore":0-100,"detectedChannel":"SMS"|"WhatsApp"|"Email"|"URL / Link"|"QR Payment","summary":"1 short sentence <=15 words","redFlags":["max 3 bullets <=9 words each"],"safeActions":["max 3 bullets <=9 words each"],"senderMismatchStatus":"Mismatch Detected"|"Potential Mismatch"|"Consistent"|"Unverified","senderMismatchDetail":"1 short sentence <=14 words","paymentTriggerCategory":"short label","paymentTriggerDetail":"1 short sentence <=14 words","paymentTriggerHighRisk":boolean}`;

const TEXT_SCAM_RESPONSE_SCHEMA = Schema.object({
  properties: {
    riskLevel: Schema.enumString({
      enum: ['Safe', 'Suspicious', 'High Risk'],
    }),
    confidenceScore: Schema.integer(),
    detectedChannel: Schema.string(),
    summary: Schema.string(),
    redFlags: Schema.array({
      items: Schema.string(),
    }),
    safeActions: Schema.array({
      items: Schema.string(),
    }),
  },
});

const VISION_SCAM_RESPONSE_SCHEMA = Schema.object({
  properties: {
    riskLevel: Schema.enumString({
      enum: ['Safe', 'Suspicious', 'High Risk'],
    }),
    confidenceScore: Schema.integer(),
    detectedChannel: Schema.string(),
    summary: Schema.string(),
    redFlags: Schema.array({
      items: Schema.string(),
    }),
    safeActions: Schema.array({
      items: Schema.string(),
    }),
    senderMismatchStatus: Schema.enumString({
      enum: ['Mismatch Detected', 'Potential Mismatch', 'Consistent', 'Unverified'],
    }),
    senderMismatchDetail: Schema.string(),
    paymentTriggerCategory: Schema.string(),
    paymentTriggerDetail: Schema.string(),
    paymentTriggerHighRisk: Schema.boolean(),
  },
});

const CLOUD_MODEL_ID = 'gemini-2.5-flash';

// Cached sessions/models reused across scans
let cachedOnDeviceSession: ChromeLanguageModelSession | null = null;
let cachedOnDeviceApiKind: OnDeviceCapability['apiKind'] | null = null;
let cachedOnDevicePromise: Promise<ChromeLanguageModelSession> | null = null;
let cachedTextCloudModel: GenerativeModel | null = null;
let cachedVisionCloudModel: GenerativeModel | null = null;

function getTextCloudModel(): GenerativeModel {
  if (!cachedTextCloudModel) {
    cachedTextCloudModel = getGenerativeModel(firebaseAI, {
      model: CLOUD_MODEL_ID,
      systemInstruction: TEXT_SYSTEM_PROMPT,
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: TEXT_SCAM_RESPONSE_SCHEMA,
        temperature: 0.1,
        maxOutputTokens: 260,
        thinkingConfig: {
          thinkingBudget: 0,
        },
      },
    });
  }
  return cachedTextCloudModel;
}

function getVisionCloudModel(): GenerativeModel {
  if (!cachedVisionCloudModel) {
    cachedVisionCloudModel = getGenerativeModel(firebaseAI, {
      model: CLOUD_MODEL_ID,
      systemInstruction: VISION_SYSTEM_PROMPT,
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: VISION_SCAM_RESPONSE_SCHEMA,
        temperature: 0.1,
        maxOutputTokens: 360,
        thinkingConfig: {
          thinkingBudget: 0,
        },
      },
    });
  }
  return cachedVisionCloudModel;
}

function getChromeGlobals(): {
  languageModel?: ChromeLanguageModelGlobal;
  legacyAI?: LegacyWindowAI;
} {
  const g = globalThis as unknown as {
    LanguageModel?: ChromeLanguageModelGlobal;
    ai?: LegacyWindowAI;
  };
  const w = typeof window !== 'undefined' ? (window as unknown as { ai?: LegacyWindowAI }) : undefined;
  return {
    languageModel: g.LanguageModel,
    legacyAI: w?.ai ?? g.ai,
  };
}

async function getOrCreateOnDeviceSession(
  apiKind: OnDeviceCapability['apiKind']
): Promise<ChromeLanguageModelSession> {
  if (cachedOnDeviceSession && cachedOnDeviceApiKind === apiKind) {
    if (
      typeof cachedOnDeviceSession.tokensLeft !== 'number' ||
      cachedOnDeviceSession.tokensLeft > 500
    ) {
      return cachedOnDeviceSession;
    }
    cachedOnDeviceSession.destroy?.();
    cachedOnDeviceSession = null;
  }

  if (cachedOnDevicePromise && cachedOnDeviceApiKind === apiKind) {
    return cachedOnDevicePromise;
  }

  const { languageModel, legacyAI } = getChromeGlobals();

  cachedOnDeviceApiKind = apiKind;
  cachedOnDevicePromise = (async () => {
    let session: ChromeLanguageModelSession;
    if (apiKind === 'LanguageModel' && languageModel) {
      session = await languageModel.create({
        initialPrompts: [{ role: 'system', content: TEXT_SYSTEM_PROMPT }],
      });
    } else if (apiKind === 'window.ai' && legacyAI?.languageModel) {
      session = await legacyAI.languageModel.create({
        systemPrompt: TEXT_SYSTEM_PROMPT,
      });
    } else {
      throw new Error('On-device Prompt API is unavailable.');
    }

    cachedOnDeviceSession = session;
    return session;
  })();

  try {
    return await cachedOnDevicePromise;
  } finally {
    cachedOnDevicePromise = null;
  }
}

export function prewarmAnalyzer(capability: OnDeviceCapability): void {
  // Pre-initialize cloud model object immediately
  getTextCloudModel();
  // Only pre-warm Chrome Built-in AI when already available (no download prompt required)
  if (capability.availability === 'available' && capability.apiKind !== 'none') {
    void getOrCreateOnDeviceSession(capability.apiKind).catch(() => {
      // Non-blocking warm-up
    });
  }
}

export async function detectOnDeviceCapability(): Promise<OnDeviceCapability> {
  if (typeof window === 'undefined') {
    return {
      availability: 'unavailable',
      apiKind: 'none',
      detail: 'Browser runtime required for Chrome Built-in AI.',
    };
  }

  const { languageModel, legacyAI } = getChromeGlobals();

  try {
    if (languageModel) {
      const status = languageModel.availability ? await languageModel.availability() : 'available';
      if (status === 'available') {
        return {
          availability: 'available',
          apiKind: 'LanguageModel',
          detail: 'Chrome Prompt API (Gemini Nano) is ready locally on this device.',
        };
      }
      if (status === 'downloadable' || status === 'downloading') {
        return {
          availability: 'downloadable',
          apiKind: 'LanguageModel',
          detail: 'Chrome Prompt API is supported and ready to initialize on-device.',
        };
      }
    }

    if (legacyAI?.languageModel) {
      const caps = await legacyAI.languageModel.capabilities();
      if (caps.available === 'readily') {
        return {
          availability: 'available',
          apiKind: 'window.ai',
          detail: 'window.ai Prompt API (Gemini Nano) is ready locally on this device.',
        };
      }
      if (caps.available === 'after-download') {
        return {
          availability: 'downloadable',
          apiKind: 'window.ai',
          detail: 'window.ai Prompt API is supported on-device after model download.',
        };
      }
    }
  } catch {
    // Fall through to unavailable
  }

  return {
    availability: 'unavailable',
    apiKind: 'none',
    detail:
      'Chrome Built-in AI (window.ai / LanguageModel) not detected in this browser; Firebase AI Logic Cloud Fallback is active.',
  };
}

function normalizeRiskLevel(value: unknown): RiskLevel {
  if (value === 'Safe' || value === 'Suspicious' || value === 'High Risk') {
    return value;
  }
  const str = String(value ?? '').toLowerCase();
  if (str.includes('high') || str.includes('scam') || str.includes('danger')) return 'High Risk';
  if (str.includes('suspicious') || str.includes('warn') || str.includes('caution')) return 'Suspicious';
  return 'Safe';
}

function normalizeMismatchStatus(
  value: unknown
): TechnicalSignalBreakdown['senderMismatch']['status'] | undefined {
  if (
    value === 'Mismatch Detected' ||
    value === 'Potential Mismatch' ||
    value === 'Consistent' ||
    value === 'Unverified'
  ) {
    return value;
  }
  return undefined;
}

function parseAIJsonResponse(rawText: string): RawAIAnalysisPayload {
  const stripped = rawText
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();

  const startIdx = stripped.indexOf('{');
  const endIdx = stripped.lastIndexOf('}');
  const jsonCandidate =
    startIdx !== -1 && endIdx > startIdx ? stripped.slice(startIdx, endIdx + 1) : stripped;

  const parsed = JSON.parse(jsonCandidate) as Partial<RawAIAnalysisPayload>;

  const confidence = Number(parsed.confidenceScore);
  const clampedConfidence = Number.isFinite(confidence)
    ? Math.max(1, Math.min(100, Math.round(confidence)))
    : 85;

  return {
    riskLevel: normalizeRiskLevel(parsed.riskLevel),
    confidenceScore: clampedConfidence,
    detectedChannel:
      typeof parsed.detectedChannel === 'string' && parsed.detectedChannel.trim()
        ? parsed.detectedChannel.trim()
        : 'Message',
    summary:
      typeof parsed.summary === 'string' && parsed.summary.trim()
        ? parsed.summary.trim()
        : 'Analysis completed.',
    redFlags:
      Array.isArray(parsed.redFlags) && parsed.redFlags.length > 0
        ? parsed.redFlags.map((item) => String(item).trim()).filter(Boolean).slice(0, 3)
        : ['No threat indicators reported.'],
    safeActions:
      Array.isArray(parsed.safeActions) && parsed.safeActions.length > 0
        ? parsed.safeActions.map((item) => String(item).trim()).filter(Boolean).slice(0, 3)
        : ['Verify sender via official channels.'],
    senderMismatchStatus: normalizeMismatchStatus(parsed.senderMismatchStatus),
    senderMismatchDetail:
      typeof parsed.senderMismatchDetail === 'string' && parsed.senderMismatchDetail.trim()
        ? parsed.senderMismatchDetail.trim()
        : undefined,
    paymentTriggerCategory:
      typeof parsed.paymentTriggerCategory === 'string' && parsed.paymentTriggerCategory.trim()
        ? parsed.paymentTriggerCategory.trim()
        : undefined,
    paymentTriggerDetail:
      typeof parsed.paymentTriggerDetail === 'string' && parsed.paymentTriggerDetail.trim()
        ? parsed.paymentTriggerDetail.trim()
        : undefined,
    paymentTriggerHighRisk:
      typeof parsed.paymentTriggerHighRisk === 'boolean'
        ? parsed.paymentTriggerHighRisk
        : undefined,
  };
}

function buildUserPrompt(
  message: string,
  channel: ChannelType,
  sourceContext: SourceContext,
  signals: ExtractedSignal[],
  uploadedImage?: UploadedEvidenceImage | null
): string {
  const signalText =
    signals.length > 0
      ? signals.map((s) => `${s.severity}:${s.kind}=${s.value} (${s.note})`).join('; ')
      : 'none';

  const imageContext = uploadedImage
    ? `\nImage: ${uploadedImage.name}${
        uploadedImage.decodedQrText ? ` | QR=${uploadedImage.decodedQrText}` : ''
      }`
    : '';

  return `Channel=${channel === 'auto' ? 'Auto' : channel} | Source=${getSourceContextLabel(sourceContext)}${imageContext}
Signals=${signalText}
Text:
${message || '(Inspect attached screenshot/QR)'}`;
}

async function runOnDevicePromptAPI(
  promptText: string,
  capability: OnDeviceCapability
): Promise<{ payload: RawAIAnalysisPayload; modelName: string }> {
  const session = await getOrCreateOnDeviceSession(capability.apiKind);

  try {
    const raw = await session.prompt(promptText);
    return {
      payload: parseAIJsonResponse(raw),
      modelName: 'Gemini Nano (Chrome Prompt API)',
    };
  } catch {
    cachedOnDeviceSession?.destroy?.();
    cachedOnDeviceSession = null;
    const freshSession = await getOrCreateOnDeviceSession(capability.apiKind);
    const raw = await freshSession.prompt(promptText);
    return {
      payload: parseAIJsonResponse(raw),
      modelName: 'Gemini Nano (Chrome Prompt API)',
    };
  }
}

async function runFirebaseCloudAI(
  promptText: string,
  uploadedImage?: UploadedEvidenceImage | null
): Promise<{ payload: RawAIAnalysisPayload; modelName: string }> {
  if (uploadedImage) {
    const model = getVisionCloudModel();
    const contentParts: Array<string | Part> = [
      promptText,
      {
        type: 'inlineData',
        inlineData: {
          mimeType: uploadedImage.mimeType,
          data: uploadedImage.base64Data,
        },
      },
    ];
    const result = await model.generateContent(contentParts);
    return {
      payload: parseAIJsonResponse(result.response.text()),
      modelName: `${CLOUD_MODEL_ID} Multimodal (Firebase AI Logic)`,
    };
  }

  const model = getTextCloudModel();
  const result = await model.generateContent(promptText);
  return {
    payload: parseAIJsonResponse(result.response.text()),
    modelName: `${CLOUD_MODEL_ID} (Firebase AI Logic)`,
  };
}

function mergeTechnicalBreakdown(
  localBreakdown: TechnicalSignalBreakdown,
  payload: RawAIAnalysisPayload
): TechnicalSignalBreakdown {
  return {
    urlParts: localBreakdown.urlParts,
    senderMismatch: {
      status: payload.senderMismatchStatus ?? localBreakdown.senderMismatch.status,
      detail: payload.senderMismatchDetail ?? localBreakdown.senderMismatch.detail,
    },
    paymentTriggerType: {
      category: payload.paymentTriggerCategory ?? localBreakdown.paymentTriggerType.category,
      detail: payload.paymentTriggerDetail ?? localBreakdown.paymentTriggerType.detail,
      isHighRisk:
        payload.paymentTriggerHighRisk ?? localBreakdown.paymentTriggerType.isHighRisk,
    },
  };
}

export interface AnalyzeOptions {
  message: string;
  channel: ChannelType;
  sourceContext: SourceContext;
  uploadedImage?: UploadedEvidenceImage | null;
  forceCloud: boolean;
  capability: OnDeviceCapability;
}

export async function analyzeScamMessage({
  message,
  channel,
  sourceContext,
  uploadedImage,
  forceCloud,
  capability,
}: AnalyzeOptions): Promise<ScamAnalysisResult> {
  const trimmed = message.trim();
  if (!trimmed && !uploadedImage) {
    throw new Error('Please paste a message/link or upload a chat screenshot / QR image.');
  }

  const startedAt = performance.now();
  const decodedQrText = uploadedImage?.decodedQrText ?? null;
  const extractedSignals = extractTechnicalSignals(trimmed, decodedQrText);
  const localBreakdown = buildLocalTechnicalBreakdown(trimmed, sourceContext, decodedQrText);
  const userPrompt = buildUserPrompt(trimmed, channel, sourceContext, extractedSignals, uploadedImage);

  let engine: ScamAnalysisResult['engine'] = 'cloud-fallback';
  let engineDetail = 'Analyzed via Firebase AI Logic (GoogleAIBackend)';
  let payload: RawAIAnalysisPayload;
  let modelName = CLOUD_MODEL_ID;

  const canTryOnDevice = !forceCloud && !uploadedImage && capability.availability !== 'unavailable';

  if (canTryOnDevice) {
    try {
      const localResult = await runOnDevicePromptAPI(userPrompt, capability);
      payload = localResult.payload;
      modelName = localResult.modelName;
      engine = 'on-device';
      engineDetail = 'Processed locally on-device via Chrome Built-in AI (Zero network egress)';
    } catch {
      const cloudResult = await runFirebaseCloudAI(userPrompt, uploadedImage);
      payload = cloudResult.payload;
      modelName = cloudResult.modelName;
      engine = 'cloud-fallback';
      engineDetail = 'On-device unavailable during execution; automatically routed to Firebase AI Logic';
    }
  } else {
    const cloudResult = await runFirebaseCloudAI(userPrompt, uploadedImage);
    payload = cloudResult.payload;
    modelName = cloudResult.modelName;
    engine = 'cloud-fallback';
    if (uploadedImage) {
      engineDetail =
        'Screenshot / QR image inspected via Gemini multimodal analysis (Firebase AI Logic)';
    } else if (forceCloud) {
      engineDetail = 'Deep Cloud Analysis enabled via Firebase AI Logic (GoogleAIBackend)';
    } else {
      engineDetail =
        'Browser lacks Chrome Built-in AI; routed to Firebase AI Logic Cloud Fallback';
    }
  }

  const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
  const technicalBreakdown = mergeTechnicalBreakdown(localBreakdown, payload);

  void trackScamEvent('scam_analysis_completed', {
    engine,
    risk_level: payload.riskLevel,
    channel: payload.detectedChannel,
    source_context: sourceContext,
    has_image: Boolean(uploadedImage),
    confidence: payload.confidenceScore,
    latency_ms: latencyMs,
  });

  const displayInput =
    trimmed ||
    (decodedQrText
      ? `[QR Image: ${uploadedImage?.name}] ${decodedQrText}`
      : `[Screenshot Image: ${uploadedImage?.name}]`);

  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    input: displayInput,
    channel,
    sourceContext,
    hasImageEvidence: Boolean(uploadedImage),
    decodedQrText,
    detectedChannel: payload.detectedChannel,
    riskLevel: payload.riskLevel,
    confidenceScore: payload.confidenceScore,
    summary: payload.summary,
    redFlags: payload.redFlags,
    safeActions: payload.safeActions,
    extractedSignals,
    technicalBreakdown,
    engine,
    engineDetail,
    modelName,
    latencyMs,
  };
}
