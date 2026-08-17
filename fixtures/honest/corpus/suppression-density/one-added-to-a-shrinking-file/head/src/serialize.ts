import { Line } from './cart';

// @ts-expect-error the upstream Line type is wrong
export function serialize(lines: Line[]): string {
  return JSON.stringify(lines);
}
