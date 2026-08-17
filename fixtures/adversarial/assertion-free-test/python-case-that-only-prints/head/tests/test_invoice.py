from invoice import subtotal


def test_subtotal_prints():
    print(subtotal([{"qty": 1, "unit_price": 2}]))
