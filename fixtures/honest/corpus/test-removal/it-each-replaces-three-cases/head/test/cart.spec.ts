import { applyDiscount } from '../src/cart';

describe('discount', () => {
  it.each([[10, 90], [50, 50], [0, 100]])(
    'applies %i percent',
    (percent, expected) => {
      expect(applyDiscount(100, percent)).toBe(expected);
    },
  );
});
