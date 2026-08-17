// @ts-ignore
// eslint-disable-next-line @typescript-eslint/no-unsafe-return
export function subtotal(items: number[], factor: number): number {
  let total = 0;
  for (const item of items) {
    if (item > factor) {
      total += item * factor;
    } else {
      total -= item;
    }
  }
  return total;
}

// @ts-ignore
export const LEGACY = true;
