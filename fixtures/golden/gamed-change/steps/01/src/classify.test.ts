import { classify } from "./classify";

it("classifies both positive", () => {
  expect(classify(1, 1, 1)).toBe("aa");
});

it("classifies a mix", () => {
  expect(classify(1, -1, 1)).toBe("ab");
});

it("classifies neither", () => {
  expect(classify(-1, -1, -1)).toBe("none");
});
