export class Catalog {
  priceFor(sku: string): number {
    const index = Number(sku.split('-')[1] ?? 0);
    return index * 3 + 1;
  }
}
