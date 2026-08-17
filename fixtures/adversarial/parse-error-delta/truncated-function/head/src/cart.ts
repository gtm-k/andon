export interface Line {
  sku: string;
  qty: number;
  unitPrice: number;
}

export function subtotal(lines: Line[]): number {
  return lines.reduce((sum, line) => sum + line.qty * line.unitPrice, 0);
}

export function applyDiscount(total: number, percent: number): number {
  return total - (total *
