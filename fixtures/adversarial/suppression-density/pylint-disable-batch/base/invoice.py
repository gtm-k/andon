"""Invoice arithmetic."""


def subtotal(lines):
    return sum(line["qty"] * line["unit_price"] for line in lines)


def apply_discount(total, percent):
    if percent < 0 or percent > 100:
        raise ValueError("percent out of range")
    return total - (total * percent) / 100
