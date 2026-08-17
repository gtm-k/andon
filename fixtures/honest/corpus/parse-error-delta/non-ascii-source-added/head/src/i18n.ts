// Übersetzungen — 翻訳 — переводы
export const grüße = {
  de: 'Grüße',
  ja: 'ごあいさつ',
  ru: 'приветствия',
};

export function greet(locale: keyof typeof grüße): string {
  return grüße[locale] ?? 'hello';
}
