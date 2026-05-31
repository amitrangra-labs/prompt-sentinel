import pytest

from prompt_sentinel.filter.engine import FilterEngine


@pytest.fixture
def engine() -> FilterEngine:
    return FilterEngine()
