import type {
  ExtractedSignal,
  ParsedUrlBreakdown,
  SourceContext,
  TechnicalSignalBreakdown,
} from '../types/scam';

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'rebrand.ly',
  'shorturl.at',
  'tiny.cc',
]);

const HIGH_RISK_TLDS = ['.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.vip', '.work'];

const URGENCY_TERMS = [
  'immediately',
  'blocked',
  'suspended',
  'expired',
  '24 hours',
  '11:59',
  'penalty',
  'verify now',
  'account will be closed',
  'kyc update',
  'rekyc',
  'legal action',
];

const INSTITUTIONAL_CLAIMS = [
  'hdfc',
  'sbi',
  'icici',
  'axis',
  'kotak',
  'paypal',
  'amazon',
  'bank',
  'kyc',
  'rbi',
  'income tax',
  'govt',
  'whatsapp',
  'fedex',
  'dhl',
  'bluedart',
];

export function extractTechnicalSignals(
  text: string,
  decodedQrText?: string | null
): ExtractedSignal[] {
  const combinedText = [text, decodedQrText ? `QR Payload: ${decodedQrText}` : '']
    .filter(Boolean)
    .join('\n');

  const signals: ExtractedSignal[] = [];
  const seen = new Set<string>();

  if (decodedQrText) {
    signals.push({
      kind: 'qr',
      value: decodedQrText,
      note: decodedQrText.toLowerCase().startsWith('upi://')
        ? 'Decoded UPI payment QR payload on-device'
        : 'Decoded QR payload on-device',
      severity: decodedQrText.toLowerCase().startsWith('upi://') ? 'warning' : 'info',
    });
  }

  // 1. Extract HTTP/HTTPS/UPI URLs
  const urlRegex = /(?:https?:\/\/|upi:\/\/)[^\s<>"')]+/gi;
  const urlMatches = combinedText.match(urlRegex) ?? [];

  for (const rawUrl of urlMatches) {
    const cleaned = rawUrl.replace(/[.,;!?]+$/, '');
    if (seen.has(`url:${cleaned}`)) continue;
    seen.add(`url:${cleaned}`);

    if (cleaned.toLowerCase().startsWith('upi://')) {
      const hasAmount = /[?&]am=\d+/i.test(cleaned);
      signals.push({
        kind: 'upi',
        value: cleaned,
        note: hasAmount
          ? 'UPI payment URI includes pre-filled debit amount'
          : 'Direct UPI payment intent link detected',
        severity: 'danger',
      });
      continue;
    }

    try {
      const parsed = new URL(cleaned);
      const host = parsed.hostname.toLowerCase();
      const isHttp = parsed.protocol === 'http:';
      const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
      const isPunycode = host.includes('xn--');
      const isShortener = URL_SHORTENERS.has(host);
      const hasRiskyTld = HIGH_RISK_TLDS.some((tld) => host.endsWith(tld));
      const hasBrandHyphenSpoof =
        host.split('-').length >= 3 &&
        /(bank|kyc|verify|secure|login|update|reward|hdfc|sbi|icici|paypal|amazon)/i.test(host);

      if (isIp || isPunycode || hasRiskyTld || hasBrandHyphenSpoof) {
        const reasons: string[] = [];
        if (isHttp) reasons.push('unencrypted HTTP');
        if (isIp) reasons.push('raw IP host');
        if (isPunycode) reasons.push('IDN/punycode spoofing');
        if (hasRiskyTld) reasons.push('high-abuse TLD');
        if (hasBrandHyphenSpoof) reasons.push('multi-hyphen brand lookalike');
        signals.push({
          kind: 'url',
          value: cleaned,
          note: `Suspicious domain (${reasons.join(', ')})`,
          severity: 'danger',
        });
      } else if (isShortener || isHttp) {
        signals.push({
          kind: 'url',
          value: cleaned,
          note: isShortener ? 'Shortened URL hides final destination' : 'Unencrypted HTTP link',
          severity: 'warning',
        });
      } else {
        signals.push({
          kind: 'url',
          value: cleaned,
          note: `HTTPS domain: ${host}`,
          severity: 'info',
        });
      }
    } catch {
      signals.push({
        kind: 'url',
        value: cleaned,
        note: 'Malformed URL syntax',
        severity: 'warning',
      });
    }
  }

  // 2. Extract standalone UPI handles (e.g., name@ybl, reward@okicici)
  const upiHandleRegex =
    /\b[a-zA-Z0-9._-]{3,}@(?:ybl|okicici|oksbi|okaxis|okhdfcbank|paytm|ibl|axl|upi)\b/gi;
  const upiMatches = combinedText.match(upiHandleRegex) ?? [];
  for (const handle of upiMatches) {
    if (seen.has(`upi:${handle.toLowerCase()}`)) continue;
    seen.add(`upi:${handle.toLowerCase()}`);
    signals.push({
      kind: 'upi',
      value: handle,
      note: 'UPI Virtual Payment Address (VPA) found',
      severity: 'warning',
    });
  }

  // 3. Extract email addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emailMatches = combinedText.match(emailRegex) ?? [];
  for (const email of emailMatches) {
    if (seen.has(`email:${email.toLowerCase()}`)) continue;
    seen.add(`email:${email.toLowerCase()}`);
    signals.push({
      kind: 'email',
      value: email,
      note: 'Email address reference',
      severity: 'info',
    });
  }

  // 4. Detect urgency/coercion phrases
  const lower = combinedText.toLowerCase();
  const matchedUrgency = URGENCY_TERMS.filter((term) => lower.includes(term));
  if (matchedUrgency.length >= 2) {
    signals.push({
      kind: 'pattern',
      value: matchedUrgency.slice(0, 3).join(', '),
      note: 'High-pressure urgency & fear triggers',
      severity: 'warning',
    });
  }

  // 5. Detect PIN/OTP/CVV solicitation
  if (
    /(enter|share|confirm|send).{0,24}(upi\s*pin|atm\s*pin|cvv|card\s*number|netbanking\s*password)/i.test(
      combinedText
    )
  ) {
    signals.push({
      kind: 'pattern',
      value: 'Credential / PIN request',
      note: 'Solicits private PIN, CVV, or banking password',
      severity: 'danger',
    });
  }

  return signals;
}

export function extractUrlParts(text: string, decodedQrText?: string | null): ParsedUrlBreakdown[] {
  const combinedText = [text, decodedQrText ?? ''].filter(Boolean).join('\n');
  const urlRegex = /(?:https?:\/\/|upi:\/\/)[^\s<>"')]+/gi;
  const matches = combinedText.match(urlRegex) ?? [];
  const seen = new Set<string>();
  const results: ParsedUrlBreakdown[] = [];

  for (const rawMatch of matches) {
    const cleaned = rawMatch.replace(/[.,;!?]+$/, '');
    if (seen.has(cleaned)) continue;
    seen.add(cleaned);

    if (cleaned.toLowerCase().startsWith('upi://')) {
      const queryIndex = cleaned.indexOf('?');
      const pathPart = queryIndex !== -1 ? cleaned.slice(queryIndex) : '';
      const params = new URLSearchParams(pathPart);
      const payee = params.get('pa') ?? 'unknown-vpa';
      const amount = params.get('am');
      const flags = ['Direct UPI payment intent'];
      if (amount) flags.push(`Pre-filled amount: ${amount}`);

      results.push({
        raw: cleaned,
        protocol: 'upi://',
        host: payee,
        tld: payee.includes('@') ? `@${payee.split('@')[1]}` : 'UPI',
        path: pathPart || '/',
        flags,
        severity: 'danger',
      });
      continue;
    }

    try {
      const parsed = new URL(cleaned);
      const host = parsed.hostname.toLowerCase();
      const hostParts = host.split('.');
      const tld = hostParts.length > 1 ? `.${hostParts[hostParts.length - 1]}` : 'N/A';
      const path = `${parsed.pathname}${parsed.search}${parsed.hash}` || '/';
      const flags: string[] = [];
      let severity: ParsedUrlBreakdown['severity'] = 'info';

      if (parsed.protocol === 'http:') {
        flags.push('Unencrypted HTTP');
        severity = 'warning';
      }
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
        flags.push('Raw IP address host');
        severity = 'danger';
      }
      if (host.includes('xn--')) {
        flags.push('Punycode / IDN spoof');
        severity = 'danger';
      }
      if (URL_SHORTENERS.has(host)) {
        flags.push('URL shortener');
        if (severity === 'info') severity = 'warning';
      }
      if (HIGH_RISK_TLDS.includes(tld)) {
        flags.push(`High-abuse TLD (${tld})`);
        severity = 'danger';
      }
      if (
        host.split('-').length >= 3 &&
        /(bank|kyc|verify|secure|login|update|reward|hdfc|sbi|icici|paypal|amazon)/i.test(host)
      ) {
        flags.push('Multi-hyphen brand lookalike');
        severity = 'danger';
      }
      if (flags.length === 0) {
        flags.push('HTTPS verified syntax');
      }

      results.push({
        raw: cleaned,
        protocol: parsed.protocol.replace(':', '://'),
        host,
        tld,
        path,
        flags,
        severity,
      });
    } catch {
      results.push({
        raw: cleaned,
        protocol: 'unknown',
        host: cleaned,
        tld: 'N/A',
        path: '/',
        flags: ['Malformed URL'],
        severity: 'warning',
      });
    }
  }

  return results;
}

export function buildLocalTechnicalBreakdown(
  text: string,
  sourceContext: SourceContext,
  decodedQrText?: string | null
): TechnicalSignalBreakdown {
  const combined = [text, decodedQrText ?? ''].filter(Boolean).join('\n');
  const lower = combined.toLowerCase();
  const urlParts = extractUrlParts(text, decodedQrText);

  const claimedEntity = INSTITUTIONAL_CLAIMS.find((term) => lower.includes(term));

  let senderMismatch: TechnicalSignalBreakdown['senderMismatch'] = {
    status: 'Unverified',
    detail: 'No explicit sender header mismatch identified from text alone.',
  };

  if (sourceContext === 'unknown-10-digit' && claimedEntity) {
    senderMismatch = {
      status: 'Mismatch Detected',
      detail: `Message references "${claimedEntity.toUpperCase()}" but arrived from an Unknown 10-Digit Number instead of an official verified sender ID.`,
    };
  } else if (sourceContext === 'unverified-account' && claimedEntity) {
    senderMismatch = {
      status: 'Mismatch Detected',
      detail: `Claims "${claimedEntity.toUpperCase()}" context from an Unverified Account.`,
    };
  } else if (sourceContext === 'forwarded-message') {
    senderMismatch = {
      status: 'Potential Mismatch',
      detail: 'Forwarded Message lacks original sender verification and commonly spreads viral prize/lottery lures.',
    };
  } else if (sourceContext === 'sms' && urlParts.some((u) => u.severity === 'danger')) {
    senderMismatch = {
      status: 'Mismatch Detected',
      detail: 'SMS claims trusted institution while linking to an unverified or lookalike domain.',
    };
  } else if (sourceContext === 'sms' && urlParts.every((u) => u.severity === 'info')) {
    senderMismatch = {
      status: 'Consistent',
      detail: 'SMS channel aligns with standard transactional notification format.',
    };
  }

  let paymentTriggerType: TechnicalSignalBreakdown['paymentTriggerType'] = {
    category: 'None Detected',
    detail: 'No direct payment link, UPI collect trigger, or credential prompt detected.',
    isHighRisk: false,
  };

  if (/upi:\/\/pay/i.test(combined) || /(upi\s*pin|enter.*pin)/i.test(combined)) {
    paymentTriggerType = {
      category: 'UPI Debit / PIN Approval Trap',
      detail: 'Triggers an outgoing UPI payment or solicits a UPI PIN under the guise of claiming funds.',
      isHighRisk: true,
    };
  } else if (/(kyc|pan|netbanking|cvv|card\s*number|login|verify-now)/i.test(combined)) {
    paymentTriggerType = {
      category: 'Credential & KYC Phishing Form',
      detail: 'Directs user to submit banking, PAN/KYC, or card credentials on an external link.',
      isHighRisk: true,
    };
  } else if (/(lottery|mega draw|cashback|won rs|prize|reward)/i.test(combined)) {
    paymentTriggerType = {
      category: 'Prize / Advance-Fee Lure',
      detail: 'Uses unsolicited reward claims to trigger payment authorization or fee transfer.',
      isHighRisk: true,
    };
  } else if (/delivery otp/i.test(combined) || /at your doorstep/i.test(combined)) {
    paymentTriggerType = {
      category: 'Doorstep Delivery Verification OTP',
      detail: 'Non-financial courier confirmation code intended only for physical handoff.',
      isHighRisk: false,
    };
  }

  return {
    urlParts,
    senderMismatch,
    paymentTriggerType,
  };
}
