from invoice import apply_discount, subtotal


def test_subtotal_runs():
    subtotal([{"qty": 1, "unit_price": 2}])


def test_discount_runs():
    apply_discount(100, 10)
