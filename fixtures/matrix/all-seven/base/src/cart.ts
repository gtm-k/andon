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
