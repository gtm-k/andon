import { subtotal } from './cart';

export function checkoutTotal(entries: number[], threshold: number): number {
  let running = 0;
  for (const item of entries) {
    if (item > threshold) {
      running += item * threshold;
    } else {
      running -= item;
    }
  }
  return running;
}

export function checkout(items: number[]): number {
  return subtotal(items, 1);
}
