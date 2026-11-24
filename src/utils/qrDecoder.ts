import jsQR from 'jsqr';
import type { UploadedEvidenceImage } from '../types/scam';

const MAX_QR_SCAN_DIMENSION = 1600;
const MAX_UPLOAD_DIMENSION = 1280;

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        resolve(reader.result);
      } else {
        reject(new Error('Could not read uploaded image.'));
      }
    };
    reader.onerror = () => reject(new Error('Failed to read image file.'));
    reader.readAsDataURL(file);
  });
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Unsupported or corrupted image file.'));
    img.src = src;
  });
}

function decodeQrFromCanvas(img: HTMLImageElement): string | null {
  try {
    const scale = Math.min(1, MAX_QR_SCAN_DIMENSION / Math.max(img.width, img.height, 1));
    const width = Math.max(1, Math.round(img.width * scale));
    const height = Math.max(1, Math.round(img.height * scale));

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    ctx.drawImage(img, 0, 0, width, height);
    const imageData = ctx.getImageData(0, 0, width, height);
    const qrResult = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth',
    });

    return qrResult?.data?.trim() || null;
  } catch {
    return null;
  }
}

function compressForFastUpload(
  img: HTMLImageElement,
  originalDataUrl: string,
  originalMimeType: string,
  originalSizeBytes: number
): { dataUrl: string; mimeType: string } {
  const needsResize =
    Math.max(img.width, img.height) > MAX_UPLOAD_DIMENSION || originalSizeBytes > 350_000;

  if (!needsResize) {
    return { dataUrl: originalDataUrl, mimeType: originalMimeType || 'image/png' };
  }

  try {
    const scale = Math.min(1, MAX_UPLOAD_DIMENSION / Math.max(img.width, img.height, 1));
    const width = Math.max(1, Math.round(img.width * scale));
    const height = Math.max(1, Math.round(img.height * scale));

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return { dataUrl: originalDataUrl, mimeType: originalMimeType || 'image/png' };
    }

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(img, 0, 0, width, height);
    const compressedUrl = canvas.toDataURL('image/jpeg', 0.85);
    return { dataUrl: compressedUrl, mimeType: 'image/jpeg' };
  } catch {
    return { dataUrl: originalDataUrl, mimeType: originalMimeType || 'image/png' };
  }
}

export async function processUploadedImage(file: File): Promise<UploadedEvidenceImage> {
  if (!file.type.startsWith('image/')) {
    throw new Error('Please upload an image file (PNG, JPG, WebP) from your gallery.');
  }

  const rawDataUrl = await readFileAsDataUrl(file);
  const img = await loadImage(rawDataUrl);
  const decodedQrText = decodeQrFromCanvas(img);

  const { dataUrl, mimeType } = compressForFastUpload(
    img,
    rawDataUrl,
    file.type,
    file.size
  );

  const commaIndex = dataUrl.indexOf(',');
  const base64Data = commaIndex !== -1 ? dataUrl.slice(commaIndex + 1) : dataUrl;

  return {
    name: file.name,
    mimeType,
    base64Data,
    previewUrl: rawDataUrl,
    sizeBytes: file.size,
    decodedQrText,
  };
}
