import { fetchInvoice } from '../src/api';

describe('api', () => {
  it('fetches an invoice', async () => {
    await fetchInvoice('inv-1');
  });
});
