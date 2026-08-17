export interface Line {
  sku: string;
  qty: number;
  unitPrice: number;
}

const lineTotal = (line: Line): number => line.qty * line.unitPrice;

export function subtotal(lines: Line[]): number {
  let total = 0;
  for (const line of lines) {
    total += lineTotal(line);
  }
  return total;
}

export function applyDiscount(total: number, percent: number): number {
  if (percent < 0 || percent > 100) {
    throw new RangeError('percent out of range');
  }
  return total - (total * percent) / 100;
}
