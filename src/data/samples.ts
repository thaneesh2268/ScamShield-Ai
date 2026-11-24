import type { SampleMessage, SourceContext } from '../types/scam';

export const SOURCE_CONTEXT_OPTIONS: Array<{ id: SourceContext; label: string }> = [
  { id: 'unspecified', label: 'Auto / Not Specified' },
  { id: 'unknown-10-digit', label: 'Unknown 10-Digit Number' },
  { id: 'forwarded-message', label: 'Forwarded Message' },
  { id: 'unverified-account', label: 'Unverified Account' },
  { id: 'sms', label: 'SMS' },
];

export function getSourceContextLabel(context: SourceContext): string {
  return SOURCE_CONTEXT_OPTIONS.find((opt) => opt.id === context)?.label ?? 'Auto / Not Specified';
}

export const SAMPLE_MESSAGES: SampleMessage[] = [
  {
    id: 'fake-bank-kyc',
    label: 'Fake Bank KYC SMS',
    channel: 'sms',
    sourceContext: 'unknown-10-digit',
    description: 'Urgent account suspension threat with shortened lookalike KYC link',
    content:
      'URGENT: Dear HDFC Bank customer, your NetBanking & Debit Card will be BLOCKED today at 11:59 PM due to expired PAN/KYC. Update immediately to avoid penalty: http://hdfc-kyc-verify-now.xyz/rekyc?id=88412',
  },
  {
    id: 'upi-lottery-scam',
    label: 'UPI Lottery Scam',
    channel: 'whatsapp',
    sourceContext: 'forwarded-message',
    description: 'Fake cashback prize requesting UPI PIN approval on a collect link',
    content:
      'Congratulations!! Your mobile number won Rs. 49,500 in the WhatsApp Diwali Mega Draw! To claim instant credit to your bank account, tap the UPI reward link and enter your 4-digit UPI PIN: upi://pay?pa=rewardclaim88@ybl&pn=MegaReward&am=4950&cu=INR (Ref: WIN-9021)',
  },
  {
    id: 'legit-delivery-alert',
    label: 'Legitimate Delivery Alert',
    channel: 'sms',
    sourceContext: 'sms',
    description: 'Standard courier shipment update without credential or payment requests',
    content:
      'BlueDart Update: Your package AWB 7749201843 from Cloudtail India is out for delivery today between 2:00 PM and 5:00 PM. Share delivery OTP 4819 only at your doorstep when handing over the parcel. Track at https://www.bluedart.com/tracking',
  },
];
