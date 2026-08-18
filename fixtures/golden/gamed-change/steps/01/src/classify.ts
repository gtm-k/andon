export function classify(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      return "aa";
    }
    return "ab";
  }
  return "none";
}
