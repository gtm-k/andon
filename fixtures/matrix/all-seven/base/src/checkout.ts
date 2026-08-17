import { subtotal } from './cart';

export function checkout(items: number[]): number {
  return subtotal(items, 1);
}
