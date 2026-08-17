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

export function tax(total: number, rate: number): number {
  if (rate < 0) {
    throw new RangeError('rate out of range');
  }
  return total * rate;
}

export function grandTotal(lines: Line[], percent: number, rate: number): number {
  const base = applyDiscount(subtotal(lines), percent);
  return base + tax(base, rate);
}

export function describe(line: Line): string {
  return `${line.qty} x ${line.sku} @ ${line.unitPrice}`;
}
