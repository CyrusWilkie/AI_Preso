"""
Shared utility for extracting individual functions from source code files.
Returns a list of {name, code, start_line, end_line} dicts.
"""

import re


def extract_functions(code, filename):
    if filename.endswith(".c") or filename.endswith(".h"):
        return _extract_c_functions(code)
    elif filename.endswith(".py"):
        return _extract_python_functions(code)
    elif filename.endswith(".php"):
        return _extract_php_functions(code)
    return [{"name": "entire_file", "code": code, "start_line": 1, "end_line": code.count("\n") + 1}]


def _extract_c_functions(code):
    functions = []
    lines = code.split("\n")

    func_pattern = re.compile(
        r'^(?:(?:static|void|int|char|double|float|long|unsigned|signed|struct|enum|'
        r'User|FILE)\s*\*?\s*)+\s*\*?\s*(\w+)\s*\([^)]*\)\s*\{'
    )

    i = 0
    while i < len(lines):
        match = func_pattern.match(lines[i])
        if match:
            func_name = match.group(1)
            start = i
            brace_depth = 0
            for j in range(i, len(lines)):
                brace_depth += lines[j].count('{') - lines[j].count('}')
                if brace_depth == 0 and j > i:
                    func_code = "\n".join(lines[start:j + 1])
                    functions.append({
                        "name": func_name,
                        "code": func_code,
                        "start_line": start + 1,
                        "end_line": j + 1,
                    })
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1

    # Capture globals/defines/structs as a preamble
    if functions:
        first_func_line = functions[0]["start_line"] - 1
        preamble = "\n".join(lines[:first_func_line]).strip()
        if preamble:
            functions.insert(0, {
                "name": "__globals__",
                "code": preamble,
                "start_line": 1,
                "end_line": first_func_line,
            })

    if not functions:
        functions.append({"name": "entire_file", "code": code, "start_line": 1, "end_line": len(lines)})

    return functions


def _extract_python_functions(code):
    functions = []
    lines = code.split("\n")

    i = 0
    while i < len(lines):
        stripped = lines[i].lstrip()

        if stripped.startswith("@app.route") or stripped.startswith("@"):
            decorator_start = i
            while i < len(lines) and lines[i].lstrip().startswith("@"):
                i += 1
            if i < len(lines) and lines[i].lstrip().startswith("def "):
                func_match = re.match(r'\s*def\s+(\w+)', lines[i])
                if func_match:
                    func_name = func_match.group(1)
                    func_indent = len(lines[i]) - len(lines[i].lstrip())
                    start = decorator_start
                    j = i + 1
                    while j < len(lines):
                        if lines[j].strip() == "":
                            j += 1
                            continue
                        line_indent = len(lines[j]) - len(lines[j].lstrip())
                        if line_indent <= func_indent and lines[j].strip():
                            break
                        j += 1
                    func_code = "\n".join(lines[start:j])
                    functions.append({
                        "name": func_name,
                        "code": func_code,
                        "start_line": start + 1,
                        "end_line": j,
                    })
                    i = j
                    continue
            i += 1
            continue

        if stripped.startswith("def "):
            func_match = re.match(r'\s*def\s+(\w+)', lines[i])
            if func_match:
                func_name = func_match.group(1)
                func_indent = len(lines[i]) - len(lines[i].lstrip())
                start = i
                j = i + 1
                while j < len(lines):
                    if lines[j].strip() == "":
                        j += 1
                        continue
                    line_indent = len(lines[j]) - len(lines[j].lstrip())
                    if line_indent <= func_indent and lines[j].strip():
                        break
                    j += 1
                func_code = "\n".join(lines[start:j])
                functions.append({
                    "name": func_name,
                    "code": func_code,
                    "start_line": start + 1,
                    "end_line": j,
                })
                i = j
                continue

        i += 1

    # Module-level code
    if functions:
        covered = set()
        for f in functions:
            for ln in range(f["start_line"] - 1, f["end_line"]):
                covered.add(ln)
        module_lines = [lines[i] for i in range(len(lines)) if i not in covered]
        module_code = "\n".join(module_lines).strip()
        if module_code:
            functions.insert(0, {
                "name": "__module__",
                "code": module_code,
                "start_line": 1,
                "end_line": 0,
            })

    if not functions:
        functions.append({"name": "entire_file", "code": code, "start_line": 1, "end_line": len(lines)})

    return functions


def _extract_php_functions(code):
    functions = []
    lines = code.split("\n")

    func_pattern = re.compile(r'^\s*function\s+(\w+)\s*\(')

    i = 0
    while i < len(lines):
        match = func_pattern.match(lines[i])
        if match:
            func_name = match.group(1)
            start = i
            brace_depth = 0
            for j in range(i, len(lines)):
                brace_depth += lines[j].count('{') - lines[j].count('}')
                if brace_depth == 0 and j > i:
                    func_code = "\n".join(lines[start:j + 1])
                    functions.append({
                        "name": func_name,
                        "code": func_code,
                        "start_line": start + 1,
                        "end_line": j + 1,
                    })
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1

    # Non-function code
    if functions:
        covered = set()
        for f in functions:
            for ln in range(f["start_line"] - 1, f["end_line"]):
                covered.add(ln)
        other_lines = [lines[i] for i in range(len(lines)) if i not in covered]
        other_code = "\n".join(other_lines).strip()
        if other_code:
            functions.insert(0, {
                "name": "__globals__",
                "code": other_code,
                "start_line": 1,
                "end_line": 0,
            })

    if not functions:
        functions.append({"name": "entire_file", "code": code, "start_line": 1, "end_line": len(lines)})

    return functions
