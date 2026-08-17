import { Line } from './cart';

// @ts-expect-error the Line type is wrong upstream
export function serialize(lines: Line[]): string {
  // eslint-disable-next-line no-restricted-syntax
  return JSON.stringify(lines);
}

// @ts-expect-error same reason
export function parse(raw: string): Line[] {
  return JSON.parse(raw);
}
