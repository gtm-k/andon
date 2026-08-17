# noqa: D100
# type: ignore
"""Invoice arithmetic."""


def subtotal(lines):
    return sum(line["qty"] * line["unit_price"] for line in lines)


def apply_discount(total, percent):
    if percent < 0 or percent > 100:
        raise ValueError("percent out of range")
    return total - (total * percent) / 100


def line_description(line):
    return "{qty} x {sku}".format(qty=line["qty"], sku=line["sku"])


def total_quantity(lines):
    return sum(line["qty"] for line in lines)


def most_expensive(lines):
    if not lines:
        return None
    return max(lines, key=lambda line: line["unit_price"])


def cheapest(lines):
    if not lines:
        return None
    return min(lines, key=lambda line: line["unit_price"])
