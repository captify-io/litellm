import pytest

from tests.documentation_tests.test_router_settings import extract_documented_router_keys


def test_router_table_reads_consecutive_rows_and_only_the_name_column():
    content = """### general_settings - Reference
| elsewhere | string | timeout |
### router_settings - Reference
| Name | Type | Default | Description |
|------|------|---------|-------------|
| redis_host | string | null | text |
| redis_port | string | null | text |
| `timeout` | float | null | undocumented_setting |
#### Details
| max_fallbacks | int | 5 | text |
### environment variables - Reference
| unrelated | string | null | text |
"""
    assert extract_documented_router_keys(content) == {"redis_host", "redis_port", "timeout", "max_fallbacks"}


def test_router_section_can_be_the_last_section():
    assert extract_documented_router_keys("### router_settings - Reference\n| timeout | float |\n") == {"timeout"}


def test_missing_router_section_is_refused():
    with pytest.raises(ValueError, match="Missing router_settings"):
        extract_documented_router_keys("### other\n| timeout | float |\n")
