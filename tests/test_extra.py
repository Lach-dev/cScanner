from scanner import (
    strip_comments,
    collect_char_arrays,
    check_unsafe_functions,
    check_memcpy_overflows,
    check_printf_format,
    check_large_stack_buffers,
)

def test_no_false_positive_on_substring():
    lines = ["mygets(buf);", "custom_strcpy(dest, src);"]
    warnings = check_unsafe_functions("test.c", lines)
    assert len(warnings) == 0

def test_unsafe_functions_in_comments_are_ignored():
    lines = [
        "/* gets(buf); */",
        "// strcpy(a, b);",
        "strncpy(dest, src, 10);"
    ]
    stripped = strip_comments(lines)
    warnings = check_unsafe_functions("test.c", stripped)
    assert len(warnings) == 0

def test_memcpy_with_variable_size_is_ignored():
    lines = ["memcpy(buf, src, n);", "memcpy(buf, src, size_var + 4);"]
    char_arrays = {"buf": 64}
    warnings = check_memcpy_overflows("test.c", lines, char_arrays)
    assert len(warnings) == 0

def test_collect_char_arrays_with_underscore_names():
    lines = ["char my_buf_1[128];", "char otherBuf[16];"]
    result = collect_char_arrays(lines)
    assert result == {"my_buf_1": 128, "otherBuf": 16}

def test_large_buffer_at_threshold_not_flagged():
    lines = ["char borderline[1024];"]
    warnings = check_large_stack_buffers("test.c", lines, threshold=1024)
    assert len(warnings) == 0

def test_printf_with_whitespace_and_variable_detected():
    lines = ["printf(  user_input  );"]
    warnings = check_printf_format("test.c", lines)
    assert len(warnings) == 1
    assert warnings[0].cwe == "CWE-134"
