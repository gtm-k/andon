"""Invoice arithmetic."""
# pylint: disable=missing-function-docstring


def subtotal(lines):  # pylint: disable=invalid-name
    return sum(line["qty"] * line["unit_price"] for line in lines)


def apply_discount(total, percent):  # pylint: disable=too-many-arguments
    if percent < 0 or percent > 100:
        raise ValueError("percent out of range")
    return total - (total * percent) / 100
