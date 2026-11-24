import { getGenerativeModel, Schema, type Part } from 'firebase/ai';
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

const SYSTEM_PROMPT = `You are ScamShield AI, an expert cybersecurity threat analyst specializing in SMS smishing, WhatsApp scams, phishing emails, UPI QR fraud, and malicious links.

Analyze the provided message, Source Context, and any uploaded chat screenshot or QR image carefully. When an image is attached, inspect visible sender headers, phone numbers, international country codes (e.g. non-local codes claiming local banks/couriers), unverified business badges, and UPI QR code details (payee VPA, merchant name, pre-filled amount).

Return ONLY valid JSON matching this structure:
{
  "riskLevel": "Safe" | "Suspicious" | "High Risk",
  "confidenceScore": number (integer 0 to 100),
  "detectedChannel": string (e.g. "SMS", "WhatsApp", "Email", "URL / Link", "QR Payment"),
  "summary": string (1-2 clear sentences explaining the verdict in plain English),
  "redFlags": string[] (2-5 concise, specific findings; if Safe, list 2-3 verified trust signals instead),
  "safeActions": string[] (2-4 concrete, actionable safety steps for the user),
  "senderMismatchStatus": "Mismatch Detected" | "Potential Mismatch" | "Consistent" | "Unverified",
  "senderMismatchDetail": string (concise note comparing visible sender header/country code/Source Context vs claimed brand),
  "paymentTriggerCategory": string (e.g. "UPI Debit / PIN Approval Trap", "Credential & KYC Phishing Form", "Prize / Advance-Fee Lure", "Doorstep Delivery Verification OTP", "None Detected"),
  "paymentTriggerDetail": string (concise explanation of what payment or credential action is triggered),
  "paymentTriggerHighRisk": boolean
}

Classification rules:
- "High Risk": Fake KYC/account suspension threats, lookalike domains (.xyz, .top, multi-hyphen brand spoofs), UPI lottery/reward links or QR codes asking for a UPI PIN to "receive" money, credential/OTP/CVV harvesting, or sender header/country-code impersonation.
- "Suspicious": Unverified shortened links, mild urgency, unsolicited offers, unknown 10-digit sender making unusual requests, or ambiguous sender context.
- "Safe": Legitimate transactional/delivery notifications with verified official HTTPS domains and no credential, PIN, or urgent payment traps.`;

const SCAM_RESPONSE_SCHEMA = Schema.object({
  properties: {
    riskLevel: Schema.enumString({
      enum: ['Safe', 'Suspicious', 'High Risk'],
      description: 'Overall threat classification',
    }),
    confidenceScore: Schema.integer({
      description: 'Confidence percentage from 0 to 100',
    }),
    detectedChannel: Schema.string({
      description: 'Detected communication channel such as SMS, WhatsApp, Email, QR Payment, or URL / Link',
    }),
    summary: Schema.string({
      description: '1 to 2 sentence plain-English explanation of the verdict',
    }),
    redFlags: Schema.array({
      items: Schema.string(),
      description: 'Specific red flags detected, or verified trust signals if Safe',
    }),
    safeActions: Schema.array({
      items: Schema.string(),
      description: 'Concrete recommended next steps for the user',
    }),
    senderMismatchStatus: Schema.enumString({
      enum: ['Mismatch Detected', 'Potential Mismatch', 'Consistent', 'Unverified'],
      description: 'Whether the sender header, country code, or source context mismatches the claimed identity',
    }),
    senderMismatchDetail: Schema.string({
      description: 'Concise analysis of sender header, country code, or source context alignment',
    }),
    paymentTriggerCategory: Schema.string({
      description: 'Short label for the detected payment or credential trigger type',
    }),
    paymentTriggerDetail: Schema.string({
      description: 'Explanation of the payment or credential trigger mechanism',
    }),
    paymentTriggerHighRisk: Schema.boolean({
      description: 'Whether the payment or credential trigger poses financial/credential theft risk',
    }),
  },
});

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
        ? parsed.redFlags.map((item) => String(item).trim()).filter(Boolean)
        : ['No explicit threat indicators reported.'],
    safeActions:
      Array.isArray(parsed.safeActions) && parsed.safeActions.length > 0
        ? parsed.safeActions.map((item) => String(item).trim()).filter(Boolean)
        : ['Verify sender identity through official channels before taking action.'],
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
      : '- No URLs, UPI IDs, or email tokens extracted from text.';

  const imageContext = uploadedImage
    ? `Attached screenshot / QR image: "${uploadedImage.name}" (${uploadedImage.mimeType}).${
        uploadedImage.decodedQrText
          ? ` Local QR decoder extracted payload: "${uploadedImage.decodedQrText}".`
          : ' Inspect the image visually for sender headers, phone numbers, country codes, unverified business tags, or QR details.'
      }`
    : 'No screenshot or QR image attached.';

  return `User-selected channel context: ${channel === 'auto' ? 'Auto-detect' : channel.toUpperCase()}
User-selected Source Context: ${getSourceContextLabel(sourceContext)}
${imageContext}

Technical signals extracted locally:
${signalText}

Message / Link text provided:
"""
${message || '(No text pasted; analyze the attached screenshot / QR image.)'}
"""`;
}

async function runOnDevicePromptAPI(
  promptText: string,
  capability: OnDeviceCapability
): Promise<{ payload: RawAIAnalysisPayload; modelName: string }> {
  const { languageModel, legacyAI } = getChromeGlobals();
  let session: ChromeLanguageModelSession | null = null;

  try {
    if (capability.apiKind === 'LanguageModel' && languageModel) {
      session = await languageModel.create({
        initialPrompts: [{ role: 'system', content: SYSTEM_PROMPT }],
      });
    } else if (capability.apiKind === 'window.ai' && legacyAI?.languageModel) {
      session = await legacyAI.languageModel.create({
        systemPrompt: SYSTEM_PROMPT,
      });
    } else {
      throw new Error('On-device Prompt API is unavailable.');
    }

    const raw = await session.prompt(promptText);
    return {
      payload: parseAIJsonResponse(raw),
      modelName: 'Gemini Nano (Chrome Prompt API)',
    };
  } finally {
    session?.destroy?.();
  }
}

async function runFirebaseCloudAI(
  promptText: string,
  uploadedImage?: UploadedEvidenceImage | null
): Promise<{ payload: RawAIAnalysisPayload; modelName: string }> {
  const candidateModels = ['gemini-2.5-flash', 'gemini-2.0-flash'];
  let lastError: unknown = null;

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

  for (const modelId of candidateModels) {
    try {
      const model = getGenerativeModel(firebaseAI, {
        model: modelId,
        systemInstruction: SYSTEM_PROMPT,
        generationConfig: {
          responseMimeType: 'application/json',
          responseSchema: SCAM_RESPONSE_SCHEMA,
        },
      });

      const result = await model.generateContent(
        contentParts.length === 1 ? promptText : contentParts
      );
      const rawText = result.response.text();
      return {
        payload: parseAIJsonResponse(rawText),
        modelName: uploadedImage
          ? `${modelId} Multimodal (Firebase AI Logic)`
          : `${modelId} (Firebase AI Logic)`,
      };
    } catch (err) {
      lastError = err;
      const errMsg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
      if (!errMsg.includes('not found') && !errMsg.includes('404') && !errMsg.includes('unsupported')) {
        throw err;
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error('Cloud AI analysis failed.');
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
  let modelName = 'gemini-2.5-flash';

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
