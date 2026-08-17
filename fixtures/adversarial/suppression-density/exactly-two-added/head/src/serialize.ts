import { Line } from './cart';

// @ts-ignore
export function serialize(lines: Line[]): string {
  return JSON.stringify(lines);
}

// @ts-ignore
export function parse(raw: string): Line[] {
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new TypeError('expected an array of lines');
  }
  return parsed as Line[];
}
