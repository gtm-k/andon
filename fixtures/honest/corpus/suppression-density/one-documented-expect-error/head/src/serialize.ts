import { Line } from './cart';

export function serialize(lines: Line[]): string {
  return JSON.stringify(lines);
}

export function parse(raw: string): Line[] {
  // @ts-expect-error JSON.parse is typed as any; the guard below narrows it
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new TypeError('expected an array of lines');
  }
  return parsed as Line[];
}
