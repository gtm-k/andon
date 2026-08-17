import { render } from '../src/render';

describe('render', () => {
  it('renders an empty invoice', () => {
    expect(render([])).toMatchSnapshot();
  });
  it('renders one line', () => {
    expect(render([{ sku: 'a', qty: 1, unitPrice: 2 }])).toMatchSnapshot();
  });
});
