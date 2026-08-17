/* eslint-disable */
import { Line } from './cart';

export function serialize(lines: Line[]): string {
  return JSON.stringify(lines);
}

export function parse(raw: string): Line[] {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new TypeError('expected an array of lines');
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return parsed as Line[];
}
