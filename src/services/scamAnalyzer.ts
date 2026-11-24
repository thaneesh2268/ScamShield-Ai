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
  clone?: () => Promise<ChromeLanguageModelSession>;
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

const SYSTEM_PROMPT = `You are ScamShield AI, a fast, accurate cybersecurity threat analyst for SMS, WhatsApp, email, UPI QR, and links.

Inspect the message, Source Context, local signals, and any attached screenshot/QR (check visible sender headers, country codes, unverified badges, and UPI QR payee/amount).

Return ONLY valid JSON:
{
  "riskLevel": "Safe" | "Suspicious" | "High Risk",
  "confidenceScore": number (0-100),
  "detectedChannel": string ("SMS" | "WhatsApp" | "Email" | "URL / Link" | "QR Payment"),
  "summary": string (1 short sentence under 18 words),
  "redFlags": string[] (max 3 brief bullets, under 10 words each; if Safe, 2-3 brief trust signals under 10 words each),
  "safeActions": string[] (max 3 brief actionable steps, under 10 words each),
  "senderMismatchStatus": "Mismatch Detected" | "Potential Mismatch" | "Consistent" | "Unverified",
  "senderMismatchDetail": string (1 short sentence under 16 words comparing sender/country code/Source Context vs claimed brand),
  "paymentTriggerCategory": string (e.g. "UPI Debit / PIN Approval Trap", "Credential & KYC Phishing Form", "Prize / Advance-Fee Lure", "Doorstep Delivery Verification OTP", "None Detected"),
  "paymentTriggerDetail": string (1 short sentence under 16 words),
  "paymentTriggerHighRisk": boolean
}

Rules:
- "High Risk": KYC suspension threats, lookalike/abusive TLDs (.xyz, .top, multi-hyphen bank spoofs), UPI reward/QR links asking for PIN to "receive" money, credential/OTP/CVV harvesting, sender/country-code impersonation.
- "Suspicious": Shortened links, mild urgency, unsolicited offers, or unverified 10-digit requests.
- "Safe": Legitimate alerts with official HTTPS domains and no PIN/credential/payment traps (doorstep delivery OTP is safe).`;

const SCAM_RESPONSE_SCHEMA = Schema.object({
  properties: {
    riskLevel: Schema.enumString({
      enum: ['Safe', 'Suspicious', 'High Risk'],
      description: 'Threat classification',
    }),
    confidenceScore: Schema.integer({
      description: 'Confidence 0-100',
    }),
    detectedChannel: Schema.string({
      description: 'Channel: SMS, WhatsApp, Email, QR Payment, or URL / Link',
    }),
    summary: Schema.string({
      description: '1 short sentence verdict under 18 words',
    }),
    redFlags: Schema.array({
      items: Schema.string(),
      description: 'Up to 3 brief bullets under 10 words each',
    }),
    safeActions: Schema.array({
      items: Schema.string(),
      description: 'Up to 3 brief action bullets under 10 words each',
    }),
    senderMismatchStatus: Schema.enumString({
      enum: ['Mismatch Detected', 'Potential Mismatch', 'Consistent', 'Unverified'],
      description: 'Sender alignment status',
    }),
    senderMismatchDetail: Schema.string({
      description: '1 short sentence under 16 words on sender/header match',
    }),
    paymentTriggerCategory: Schema.string({
      description: 'Payment or credential trigger label',
    }),
    paymentTriggerDetail: Schema.string({
      description: '1 short sentence under 16 words explaining trigger',
    }),
    paymentTriggerHighRisk: Schema.boolean({
      description: 'True if financial or credential theft risk',
    }),
  },
});

const CLOUD_MODEL_ID = 'gemini-2.5-flash';

// Cached AI sessions/models reused across scans for 1-3s latency
let cachedOnDeviceSession: ChromeLanguageModelSession | null = null;
let cachedOnDeviceApiKind: OnDeviceCapability['apiKind'] | null = null;
let cachedOnDevicePromise: Promise<ChromeLanguageModelSession> | null = null;
let cachedCloudModel: GenerativeModel | null = null;

function getCloudModel(): GenerativeModel {
  if (!cachedCloudModel) {
    cachedCloudModel = getGenerativeModel(firebaseAI, {
      model: CLOUD_MODEL_ID,
      systemInstruction: SYSTEM_PROMPT,
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: SCAM_RESPONSE_SCHEMA,
        temperature: 0.1,
        maxOutputTokens: 450,
        thinkingConfig: {
          thinkingBudget: 0,
        },
      },
    });
  }
  return cachedCloudModel;
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
      cachedOnDeviceSession.tokensLeft > 450
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
        initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }],
      });
    } else if (apiKind === 'window.ai' && legacyAI?.languageModel) {
      session = await legacyAI.languageModel.create({
        systemPrompt: SYSTEM_PROMPT,
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
      ? signals.map((s) => `- [${s.severity.toUpperCase()}] ${s.kind}: ${s.value} (${s.note})`).join('\n')
      : '- None';

  const imageContext = uploadedImage
    ? `Image attached: "${uploadedImage.name}".${
        uploadedImage.decodedQrText
          ? ` Decoded QR: "${uploadedImage.decodedQrText}".`
          : ' Inspect visible sender headers, country codes, badges, and QR details.'
      }`
    : '';

  return `Channel: ${channel === 'auto' ? 'Auto' : channel.toUpperCase()} | Source: ${getSourceContextLabel(sourceContext)}
${imageContext ? `${imageContext}\n` : ''}Signals:
${signalText}

Content:
"""
${message || '(Analyze attached screenshot / QR image.)'}
"""`;
}

async function runOnDevicePromptAPI(
  promptText: string,
  capability: OnDeviceCapability
): Promise<{ payload: RawAIAnalysisPayload; modelName: string }> {
  const baseSession = await getOrCreateOnDeviceSession(capability.apiKind);

  const runPrompt = async (session: ChromeLanguageModelSession): Promise<string> => {
    if (typeof session.clone === 'function') {
      const cloned = await session.clone();
      try {
        return await cloned.prompt(promptText);
      } finally {
        cloned.destroy?.();
      }
    }
    return session.prompt(promptText);
  };

  try {
    const raw = await runPrompt(baseSession);
    return {
      payload: parseAIJsonResponse(raw),
      modelName: 'Gemini Nano (Chrome Prompt API)',
    };
  } catch {
    // Reset stale cached session once and retry
    cachedOnDeviceSession?.destroy?.();
    cachedOnDeviceSession = null;
    const freshSession = await getOrCreateOnDeviceSession(capability.apiKind);
    const raw = await runPrompt(freshSession);
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
  const model = getCloudModel();

  const contentParts: Array<string | Part> = uploadedImage
    ? [
        promptText,
        {
          type: 'inlineData',
          inlineData: {
            mimeType: uploadedImage.mimeType,
            data: uploadedImage.base64Data,
          },
        },
      ]
    : [promptText];

  const result = await model.generateContent(
    contentParts.length === 1 ? promptText : contentParts
  );
  const rawText = result.response.text();

  return {
    payload: parseAIJsonResponse(rawText),
    modelName: uploadedImage
      ? `${CLOUD_MODEL_ID} Multimodal (Firebase AI Logic)`
      : `${CLOUD_MODEL_ID} (Firebase AI Logic)`,
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

  // Multimodal image uploads route to Gemini multimodal on Firebase AI Logic so visible headers, country codes, and QR layouts are inspected visually
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
