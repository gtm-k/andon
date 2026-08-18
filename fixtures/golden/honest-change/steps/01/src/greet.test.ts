import { greet } from "./greet";

it("greets a named person", () => {
  expect(greet("ada")).toBe("hello, ada");
});

it("greets an anonymous one", () => {
  expect(greet("")).toBe("hello, stranger");
});
