export interface Line {
  sku: string;
  qty: number;
  unitPrice: number;
}

export function subtotal(lines: Line[]): number {
  return lines.reduce((sum, line) => sum + line.qty * line.unitPrice, 0);
}

export function applyDiscount(total: number, percent: number): number {
  if (percent < 0 || percent > 100) {
    throw new RangeError('percent out of range');
  }
  return total - (total * percent) / 100;
}
