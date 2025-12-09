import os
import tempfile
from scanner import (
    strip_comments,
    collect_char_arrays,
    check_unsafe_functions,
    check_memcpy_overflows,
    check_printf_format,
    scan_file,
    scan_path,
    check_large_stack_buffers,
    check_alloca_usage,
)

class TestStripComments:
    def test_single_line_comment(self):
        lines = ["int x = 5; // this is a comment"]
        result = strip_comments(lines)
        assert result == ["int x = 5; "]

    def test_block_comment_single_line(self):
        lines = ["int x = /* comment */ 5;"]
        result = strip_comments(lines)
        assert result == ["int x =  5;"]

    def test_block_comment_multiline(self):
        lines = ["int x = /* start", "middle", "end */ 5;"]
        result = strip_comments(lines)
        assert result == ["int x = ", "", " 5;"]

    def test_no_comments(self):
        lines = ["int x = 5;", "int y = 10;"]
        result = strip_comments(lines)
        assert result == lines

    def test_multiple_block_comments_same_line(self):
        lines = ["int /* a */ x /* b */ = 5;"]
        result = strip_comments(lines)
        assert result == ["int  x  = 5;"]

    def test_empty_input(self):
        assert strip_comments([]) == []

    def test_only_comment(self):
        lines = ["// entire line is comment"]
        result = strip_comments(lines)
        assert result == [""]

    def test_nested_block_comment_markers(self):
        lines = ["/* outer /* inner */ still comment */"]
        result = strip_comments(lines)
        assert result == [" still comment */"]


class TestCollectCharArrays:
    def test_simple_declaration(self):
        lines = ["char buffer[64];"]
        result = collect_char_arrays(lines)
        assert result == {"buffer": 64}

    def test_multiple_declarations(self):
        lines = ["char buf1[32];", "char buf2[128];"]
        result = collect_char_arrays(lines)
        assert result == {"buf1": 32, "buf2": 128}

    def test_no_char_arrays(self):
        lines = ["int x = 5;", "float y = 3.14;"]
        result = collect_char_arrays(lines)
        assert result == {}

    def test_with_spaces(self):
        lines = ["char   name  [  100  ];"]
        result = collect_char_arrays(lines)
        assert result == {"name": 100}


class TestCheckUnsafeFunctions:
    def test_gets_detected(self):
        lines = ["gets(buffer);"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 1
        assert warnings[0].cwe == "CWE-242"
        assert "gets" in warnings[0].message

    def test_strcpy_detected(self):
        lines = ["strcpy(dest, src);"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 1
        assert warnings[0].cwe == "CWE-120"

    def test_sprintf_detected(self):
        lines = ["sprintf(buf, \"%s\", str);"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 1
        assert warnings[0].severity == "MED"

    def test_no_unsafe_functions(self):
        lines = ["strncpy(dest, src, sizeof(dest));"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 0

    def test_multiple_unsafe_functions(self):
        lines = ["gets(buf);", "strcpy(a, b);", "strcat(c, d);"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 3


class TestCheckMemcpyOverflows:
    def test_overflow_detected(self):
        lines = ["memcpy(buf, src, 128);"]
        char_arrays = {"buf": 64}
        warnings = check_memcpy_overflows("test.c", lines, char_arrays)
        assert len(warnings) == 1
        assert "128 bytes" in warnings[0].message
        assert "64 bytes" in warnings[0].message

    def test_no_overflow(self):
        lines = ["memcpy(buf, src, 32);"]
        char_arrays = {"buf": 64}
        warnings = check_memcpy_overflows("test.c", lines, char_arrays)
        assert len(warnings) == 0

    def test_unknown_buffer(self):
        lines = ["memcpy(unknown, src, 128);"]
        char_arrays = {"buf": 64}
        warnings = check_memcpy_overflows("test.c", lines, char_arrays)
        assert len(warnings) == 0


class TestCheckPrintfFormat:
    def test_variable_format_string(self):
        lines = ["printf(user_input);"]
        warnings = check_printf_format("test.c", lines)
        assert len(warnings) == 1
        assert warnings[0].cwe == "CWE-134"

    def test_literal_format_string(self):
        lines = ['printf("Hello %s", name);']
        warnings = check_printf_format("test.c", lines)
        assert len(warnings) == 0

    def test_no_printf(self):
        lines = ["int x = 5;"]
        warnings = check_printf_format("test.c", lines)
        assert len(warnings) == 0


class TestScanFile:
    def test_scan_file_with_issues(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False
        ) as f:
            f.write("char buf[32];\n")
            f.write("gets(buf);\n")
            f.write("strcpy(dest, src);\n")
            f.name
        try:
            warnings = scan_file(f.name)
            assert len(warnings) == 2
        finally:
            os.unlink(f.name)

    def test_scan_file_no_issues(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False
        ) as f:
            f.write("int main() { return 0; }\n")
        try:
            warnings = scan_file(f.name)
            assert len(warnings) == 0
        finally:
            os.unlink(f.name)

    def test_nonexistent_file(self):
        warnings = scan_file("/nonexistent/path/file.c")
        assert warnings == []

    def test_binary_file_handling(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
        try:
            warnings = scan_file(f.name)
            assert isinstance(warnings, list)
        finally:
            os.unlink(f.name)


class TestScanPath:
    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            c_file = os.path.join(tmpdir, "test.c")
            with open(c_file, "w") as f:
                f.write("gets(buf);\n")

            h_file = os.path.join(tmpdir, "test.h")
            with open(h_file, "w") as f:
                f.write("strcpy(a, b);\n")

            txt_file = os.path.join(tmpdir, "readme.txt")
            with open(txt_file, "w") as f:
                f.write("gets(ignored);\n")

            warnings = scan_path(tmpdir)
            assert len(warnings) == 2

    def test_scan_single_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False
        ) as f:
            f.write("gets(buf);\n")
        try:
            warnings = scan_path(f.name)
            assert len(warnings) == 1
        finally:
            os.unlink(f.name)

    def test_scan_non_c_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("gets(buf);\n")
        try:
            warnings = scan_path(f.name)
            assert len(warnings) == 0
        finally:
            os.unlink(f.name)

class TestCheckLargeStackBuffers:
    def test_large_buffer_detected(self):
        lines = ["char huge[8192];"]
        warnings = check_large_stack_buffers("test.c", lines, threshold=1024)
        assert len(warnings) == 1

    def test_small_buffer_ok(self):
        lines = ["char small[64];"]
        warnings = check_large_stack_buffers("test.c", lines, threshold=1024)
        assert len(warnings) == 0


class TestCheckAllocaUsage:
    def test_alloca_detected(self):
        lines = ["void* p = alloca(size);"]
        warnings = check_alloca_usage("test.c", lines)
        assert len(warnings) == 1

class TestEdgeCases:
    def test_no_false_positive_on_substring(self):
        lines = ["mygets(buf);", "custom_strcpy(dest, src);"]
        warnings = check_unsafe_functions("test.c", lines)
        assert len(warnings) == 0

    def test_unsafe_functions_in_comments_are_ignored(self):
        lines = [
            "/* gets(buf); */",
            "// strcpy(a, b);",
            "strncpy(dest, src, 10);"
        ]
        stripped = strip_comments(lines)
        warnings = check_unsafe_functions("test.c", stripped)
        assert len(warnings) == 0

    def test_memcpy_with_variable_size_is_ignored(self):
        lines = ["memcpy(buf, src, n);", "memcpy(buf, src, size_var + 4);"]
        char_arrays = {"buf": 64}
        warnings = check_memcpy_overflows("test.c", lines, char_arrays)
        assert len(warnings) == 0

    def test_collect_char_arrays_with_underscore_names(self):
        lines = ["char my_buf_1[128];", "char otherBuf[16];"]
        result = collect_char_arrays(lines)
        assert result == {"my_buf_1": 128, "otherBuf": 16}

    def test_large_buffer_at_threshold_not_flagged(self):
        lines = ["char borderline[1024];"]
        warnings = check_large_stack_buffers("test.c", lines, threshold=1024)
        assert len(warnings) == 0

    def test_printf_with_whitespace_and_variable_detected(self):
        lines = ["printf(  user_input  );"]
        warnings = check_printf_format("test.c", lines)
        assert len(warnings) == 1
        assert warnings[0].cwe == "CWE-134"
