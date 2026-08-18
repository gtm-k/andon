export function classifyVariant(a: number, b: number, c: number): string {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        return "aaa";
      }
      return "aab";
    }
    if (c > 0) {
      return "aba";
    }
    return "abb";
  }
  if (b > 0) {
    if (c > 0) {
      return "baa";
    }
    return "bab";
  }
  if (c > 0) {
    if (a < -10) {
      return "bba";
    }
    return "bbb";
  }
  if (a > 1000) {
    return "big-a";
  }
  if (b > 1000) {
    return "big-b";
  }
  if (c > 1000) {
    return "big-c";
  }
  if (a > 2000) {
    return "huge-a";
  }
  if (a < -100 && b < -100) {
    return "cccc";
  }
  return "none";
}
