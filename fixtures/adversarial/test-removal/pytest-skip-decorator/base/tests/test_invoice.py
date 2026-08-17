from invoice import apply_discount, subtotal


def test_subtotal_of_nothing_is_zero():
    assert subtotal([]) == 0


def test_subtotal_sums_lines():
    assert subtotal([{"qty": 2, "unit_price": 5}]) == 10


def test_discount_rejects_out_of_range():
    try:
        apply_discount(100, 140)
    except ValueError:
        return
    raise AssertionError("expected ValueError")
