import { shout } from "./shout";

it("shouts", () => {
  expect(shout("hello")).toBe("HELLO!");
});
