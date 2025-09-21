# app/select.py

import re
from datetime import date

def process_select(code: str) -> str:
    """
    Remediate ABAP SELECT SINGLE statements according to the rules:
      1. Detect each SELECT query (single- or multi-line) that starts with SELECT SINGLE,
         with or without JOINs and with arbitrary clause order.
      2. Restructure the whole SELECT query:
         - Remove SINGLE
         - Remove any existing "UP TO <n> ROWS" if present
         - Insert "UP TO 1 ROWS" just before the first WHERE clause if present;
           otherwise insert just after the end of the INTO clause if present;
           otherwise insert before the terminating period.
      3. After the terminating period of the SELECT, add ENDSELECT. (only if not already present)
      4. Add a PwC tag comment only above each SELECT statement that was changed:
         " Added By Pwc YYYY-MM-DD
      5. Avoid changing commented or string-literal content.
    """

    pwc_tag_line = f'" Added By Pwc {date.today().isoformat()}\n'

    # Character classes used for "word boundary" checks
    def is_word_char(c: str) -> bool:
        return c.isalnum() or c == '_'

    # Case-insensitive match of a whole keyword at position i, with word boundaries.
    def match_kw_at(s: str, i: int, kw: str) -> bool:
        n = len(kw)
        if i < 0 or i + n > len(s):
            return False
        if s[i:i+n].lower() != kw.lower():
            return False
        left_ok = (i == 0) or (not is_word_char(s[i-1]))
        right_ok = (i + n == len(s)) or (not is_word_char(s[i+n]))
        return left_ok and right_ok

    # Skip whitespace and line-comments starting with " and full-line comments starting with * in col 1.
    def skip_ws_and_comments(s: str, i: int) -> int:
        length = len(s)
        while i < length:
            # Skip whitespace
            while i < length and s[i] in (' ', '\t', '\r', '\n'):
                i += 1
            if i >= length:
                return i
            # Full-line '*' comment (only if at start of a line)
            if s[i] == '*':
                # Only if at start of line
                j = i - 1
                at_bol = (i == 0) or (s[j] == '\n')
                if at_bol:
                    # consume until next newline
                    while i < length and s[i] != '\n':
                        i += 1
                    continue
            # Inline comment starts with double quote " (outside strings)
            if s[i] == '"':
                # consume until EOL
                while i < length and s[i] != '\n':
                    i += 1
                continue
            break
        return i

    # Find the end index (position of '.') that terminates an ABAP statement starting at 'start'
    # while respecting strings (single quotes '...', backticks `...`, string templates |...|)
    # and ignoring periods inside strings or comments.
    def find_statement_period(s: str, start: int) -> int:
        i = start
        length = len(s)
        in_sq = False   # '...'
        in_bt = False   # `...`
        in_tpl = False  # |...|
        while i < length:
            c = s[i]
            # Handle line comments if not in string/template
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    # skip to end of line
                    while i < length and s[i] != '\n':
                        i += 1
                    continue
                # full-line '*' comment only if at BOL
                if c == '*':
                    j = i - 1
                    if i == 0 or s[j] == '\n':
                        # skip to end of line
                        while i < length and s[i] != '\n':
                            i += 1
                        continue
            # Enter/exit string states
            if not (in_sq or in_bt or in_tpl):
                if c == "'":
                    in_sq = True
                    i += 1
                    continue
                if c == '`':
                    in_bt = True
                    i += 1
                    continue
                if c == '|':
                    in_tpl = True
                    i += 1
                    continue
            else:
                if in_sq:
                    if c == "'":
                        # doubled '' inside string -> escape
                        if i + 1 < length and s[i+1] == "'":
                            i += 2
                            continue
                        in_sq = False
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < length and s[i+1] == '`':
                            i += 2
                            continue
                        in_bt = False
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < length and s[i+1] == '|':
                            i += 2
                            continue
                        in_tpl = False
                    i += 1
                    continue
            # Check for period terminator
            if c == '.':
                return i
            i += 1
        return -1

    # Find first occurrence (index) of a keyword outside strings/comments with word boundaries
    def find_kw(s: str, kw: str, start: int = 0) -> int:
        i = start
        length = len(s)
        in_sq = in_bt = in_tpl = False
        while i < length:
            c = s[i]
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    # skip to EOL
                    while i < length and s[i] != '\n':
                        i += 1
                    i += 1
                    continue
                if c == '*':
                    j = i - 1
                    if i == 0 or s[j] == '\n':
                        while i < length and s[i] != '\n':
                            i += 1
                        i += 1
                        continue
                # possible match
                if match_kw_at(s, i, kw):
                    return i
                # fast-skip if current char cannot start keyword
                i += 1
                continue
            # inside string/template
            if in_sq:
                if c == "'":
                    if i + 1 < length and s[i+1] == "'":
                        i += 2
                        continue
                    in_sq = False
                i += 1
                continue
            if in_bt:
                if c == '`':
                    if i + 1 < length and s[i+1] == '`':
                        i += 2
                        continue
                    in_bt = False
                i += 1
                continue
            if in_tpl:
                if c == '|':
                    if i + 1 < length and s[i+1] == '|':
                        i += 2
                        continue
                    in_tpl = False
                i += 1
                continue
            i += 1
        return -1

    # Find earliest occurrence among keywords list after 'start'
    # Returns (index, keyword) or (-1, None)
    def find_next_any_kw(s: str, keywords, start: int) -> tuple[int, str | None]:
        best_idx = -1
        best_kw = None
        for kw in keywords:
            idx = find_kw(s, kw, start)
            if idx != -1 and (best_idx == -1 or idx < best_idx):
                best_idx = idx
                best_kw = kw
        return best_idx, best_kw

    # Determine if s[pos:] begins with "UP TO <n> ROWS" ignoring case and spacing
    up_to_rows_re = re.compile(r'\bUP\s+TO\s+\d+\s+ROWS\b', re.IGNORECASE)

    # Remove SINGLE (case-insensitive) as a standalone word
    def remove_single(stmt: str) -> str:
        return re.sub(r'(?i)\bSINGLE\b', '', stmt)

    # Remove any existing "UP TO n ROWS"
    def remove_any_up_to_rows(stmt: str) -> str:
        return up_to_rows_re.sub('', stmt)

    # Normalize multiple spaces but preserve newlines and tabs
    def normalize_spaces(stmt: str) -> str:
        # Replace runs of spaces with single space, but do not collapse newlines/tabs.
        def repl(m):
            s = m.group(0)
            # If contains newline/tab, keep as is
            if '\n' in s or '\t' in s:
                return s
            return ' '
        return re.sub(r'[ \t]+', repl, stmt)

    # Check if "ENDSELECT." already exists immediately after the statement end,
    # skipping whitespace and comment-only lines.
    def has_endselect_after(s: str, period_pos: int) -> bool:
        i = period_pos + 1
        i = skip_ws_and_comments(s, i)
        # Now match ENDSELECT.
        if i < len(s) and s[i:i+10].lower() == 'endselect.':
            return True
        return False

    out_parts = []
    i = 0
    n = len(code)

    while i < n:
        # Skip whitespace/comments to find potential "select"
        j = i
        # Do not skip comments globally; we need to output original content as-is.
        # We only detect SELECT SINGLE when not in string/template/comment contexts.
        # Implement a local context scan from current position to find 'select'.
        found = False

        # Lightweight scanner to find next top-level "select"
        scan_k = i
        in_sq = in_bt = in_tpl = False
        while scan_k < n:
            c = code[scan_k]
            if not (in_sq or in_bt or in_tpl):
                # start of inline comment
                if c == '"':
                    # emit code up to this char later; but for detection, skip to EOL
                    eol = code.find('\n', scan_k)
                    if eol == -1:
                        # append rest and finish
                        out_parts.append(code[i:])
                        return ''.join(out_parts)
                    scan_k = eol + 1
                    continue
                # full-line '*' comment only if at BOL
                if c == '*':
                    prev = scan_k - 1
                    if scan_k == 0 or code[prev] == '\n':
                        # at start of line; this is a comment line, skip
                        eol = code.find('\n', scan_k)
                        if eol == -1:
                            out_parts.append(code[i:])
                            return ''.join(out_parts)
                        scan_k = eol + 1
                        continue
                if c == "'":
                    in_sq = True
                    scan_k += 1
                    continue
                if c == '`':
                    in_bt = True
                    scan_k += 1
                    continue
                if c == '|':
                    in_tpl = True
                    scan_k += 1
                    continue
                # potential 'select' start
                if code[scan_k:scan_k+6].lower() == 'select' and (scan_k+6 <= n) and (scan_k+6 == n or not is_word_char(code[scan_k+6])):
                    # Now verify next token after whitespace/comments is SINGLE
                    after = scan_k + 6
                    # Skip whitespace and comments
                    while True:
                        # whitespace
                        while after < n and code[after] in (' ', '\t', '\r', '\n'):
                            after += 1
                        if after < n and code[after] == '"':
                            eol = code.find('\n', after)
                            if eol == -1:
                                eol = n - 1
                            after = eol + 1
                            continue
                        if after < n and code[after] == '*':
                            prev = after - 1
                            if after == 0 or code[prev] == '\n':
                                eol = code.find('\n', after)
                                if eol == -1:
                                    eol = n - 1
                                after = eol + 1
                                continue
                        break
                    if after < n and code[after:after+6].lower() == 'single' and (after+6 == n or not is_word_char(code[after+6])):
                        # Found SELECT SINGLE
                        found = True
                        sel_start = scan_k
                        break
                scan_k += 1
                continue
            # inside string/template
            if in_sq:
                if c == "'":
                    if scan_k + 1 < n and code[scan_k+1] == "'":
                        scan_k += 2
                        continue
                    in_sq = False
                scan_k += 1
                continue
            if in_bt:
                if c == '`':
                    if scan_k + 1 < n and code[scan_k+1] == '`':
                        scan_k += 2
                        continue
                    in_bt = False
                scan_k += 1
                continue
            if in_tpl:
                if c == '|':
                    if scan_k + 1 < n and code[scan_k+1] == '|':
                        scan_k += 2
                        continue
                    in_tpl = False
                scan_k += 1
                continue

        if not found:
            # No more SELECT SINGLE; append remainder and finish
            out_parts.append(code[i:])
            break

        # Append content before the SELECT SINGLE as-is
        out_parts.append(code[i:sel_start])

        # Find end of the SELECT statement period
        period_pos = find_statement_period(code, sel_start)
        if period_pos == -1:
            # Malformed (no period); do not modify; append rest and stop
            out_parts.append(code[sel_start:])
            break

        stmt = code[sel_start:period_pos]  # exclude period
        # For indentation and tag placement, find line start and indent
        line_start = code.rfind('\n', 0, sel_start)
        if line_start == -1:
            line_start = 0
        else:
            line_start += 1
        indent = ''
        k = line_start
        while k < sel_start and code[k] in (' ', '\t'):
            indent += code[k]
            k += 1

        # Transform the statement
        # 1) Remove SINGLE
        stmt_wo_single = remove_single(stmt)

        # 2) Remove any existing UP TO n ROWS
        stmt_wo_single_up = remove_any_up_to_rows(stmt_wo_single)

        # Use this cleaned stmt to decide insertion points
        # Note: we operate on the cleaned string but preserve other content.
        cleaned = stmt_wo_single_up

        # 3) Decide insertion position for "UP TO 1 ROWS"
        where_idx = find_kw(cleaned, 'where', 0)
        into_idx = -1 if where_idx != -1 else find_kw(cleaned, 'into', 0)

        # Compose the new statement by inserting at the right spot
        insert_phrase = ' UP TO 1 ROWS'

        if where_idx != -1:
            # Insert immediately before WHERE
            new_stmt = cleaned[:where_idx].rstrip() + insert_phrase + ' ' + cleaned[where_idx:].lstrip()
        elif into_idx != -1:
            # Insert immediately after the end of INTO clause
            search_start = into_idx + 4  # len('into')
            # Skip any spaces after 'INTO'
            while search_start < len(cleaned) and cleaned[search_start].isspace():
                search_start += 1

            # Keywords that can validly follow the INTO target; when encountered, INTO clause ends.
            # We purposely include: FROM, WHERE, ORDER, GROUP, HAVING, BYPASSING, CLIENT, USING,
            # FOR (UPDATE), APPENDING, UNION, INTERSECT, EXCEPT, PACKAGE, UP (TO)
            terminators = ['from', 'where', 'order', 'group', 'having',
                           'bypassing', 'client', 'using', 'for',
                           'appending', 'union', 'intersect', 'except',
                           'package', 'up']
            next_idx, _ = find_next_any_kw(cleaned, terminators, search_start)
            if next_idx == -1:
                # Insert before end of statement (cleaned has no period)
                new_stmt = cleaned.rstrip() + insert_phrase
            else:
                # Insert right before the next clause begins
                left = cleaned[:next_idx].rstrip()
                right = cleaned[next_idx:].lstrip()
                # Ensure a single space before the next clause
                new_stmt = f"{left}{insert_phrase} {right}"
        else:
            # No WHERE and no INTO found; append before end
            new_stmt = cleaned.rstrip() + insert_phrase

        # 4) Normalize spaces (do not collapse newlines/tabs)
        new_stmt = normalize_spaces(new_stmt).strip()

        # 5) Prepare the final replacement text including the terminating period and ENDSELECT.
        after_period_pos = period_pos + 1

        # Determine whether ENDSELECT. already present after statement
        add_endselect = not has_endselect_after(code, period_pos)

        replacement = []
        # PwC tag line with the same indentation as the SELECT line
        replacement.append(indent + pwc_tag_line)
        # Reconstructed SELECT statement plus period
        replacement.append(new_stmt + '.')
        # Add ENDSELECT on a new line with the same indentation, if not already present
        if add_endselect:
            replacement.append('\n' + indent + 'ENDSELECT.')

        # Preserve any whitespace (including newlines) immediately after the original period,
        # but stop before any existing ENDSELECT. we detected earlier.
        trailing = ''
        if not add_endselect:
            # If we did not add ENDSELECT, nothing to add here except original trailing whitespace/comments as-is
            # We'll preserve all original text up to the start of ENDSELECT.
            # Find the start of "ENDSELECT." after the period.
            k = period_pos + 1
            # Accumulate everything until 'ENDSELECT.'
            accum_start = k
            k = skip_ws_and_comments(code, k)
            # Between accum_start and k is whitespace/comments which we can preserve
            trailing = code[period_pos+1:k]
            # Then we'll leave existing ENDSELECT in place by not touching it (it will remain in the remainder appended below)

        out_parts.append(''.join(replacement) + trailing)

        # Advance i to right after the original period; if we added ENDSELECT, we also skip over nothing in original code,
        # because we have injected it. If we did not add ENDSELECT (it existed), we must not duplicate it; we will continue from period+1.
        i = after_period_pos

    return ''.join(out_parts)