import pytest

from invoice import apply_discount


def test_rejects_out_of_range():
    with pytest.raises(ValueError):
        apply_discount(100, 140)
