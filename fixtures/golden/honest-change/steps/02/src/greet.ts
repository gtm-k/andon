export function greet(name: string, formal: boolean): string {
  if (name.length === 0) {
    return "hello, stranger";
  }
  if (formal) {
    return `good day, ${name}`;
  }
  return `hello, ${name}`;
}
