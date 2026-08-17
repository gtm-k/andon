"""Invoice arithmetic."""  # noqa: D400


def subtotal(lines):  # noqa: ANN001
    return sum(line["qty"] * line["unit_price"] for line in lines)


def apply_discount(total, percent):  # noqa: ANN001, C901
    if percent < 0 or percent > 100:
        raise ValueError("percent out of range")  # noqa: TRY003
    return total - (total * percent) / 100  # noqa: E501
