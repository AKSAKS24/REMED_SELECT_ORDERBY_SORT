# app/sort.py

import re
from datetime import date

def process_sort(code: str) -> str:
    """
    Remediate ABAP SELECT statements that:
      1) Contain "FOR ALL ENTRIES" (with or without JOINs).
      2) Do not have a SORT <itab> statement as the next executable statement
         (ignoring blank/comment-only lines) after the terminating period.

    Action:
      - Insert "SORT <itab> BY <fields>." immediately after the SELECT statement period.
      - If the SELECT list is "*" or cannot be reliably extracted, insert "SORT <itab>."
      - Add PwC tag comment line directly after the inserted SORT line:
          " Added By Pwc YYYY-MM-DD
      - Only modify real ABAP code (ignore commented or string-literal content).

    Notes:
      - Supports single- or multi-line statements, JOINs, DISTINCT, aliases (AS),
        inline declarations @DATA(...), INTO/APPENDING TABLE, INTO CORRESPONDING FIELDS OF TABLE,
        and escaped host variables with '@'.
      - "SORT ... BY ..." fields are derived from the SELECT list using aliases when present.
        For items like a~field, the component name 'field' is used.
      - If the first next executable statement (after blanks/comments) is already
        "SORT <itab> ..." it will not insert another one.
    """

    pwc_tag_line = f'" Added By Pwc {date.today().isoformat()}\n'

    # ----------------- Lexical utilities (skip comments/strings) -----------------

    def is_word_char(c: str) -> bool:
        return c.isalnum() or c == '_'

    def match_kw_at(s: str, i: int, kw: str) -> bool:
        n = len(kw)
        if i < 0 or i + n > len(s):
            return False
        if s[i:i+n].lower() != kw.lower():
            return False
        left_ok = (i == 0) or (not is_word_char(s[i-1]))
        right_ok = (i + n == len(s)) or (not is_word_char(s[i+n]))
        return left_ok and right_ok

    def skip_line_comment(s: str, i: int) -> int:
        # Assumes s[i] == '"'; returns index at end-of-line (position of '\n' or len)
        eol = s.find('\n', i)
        return len(s) if eol == -1 else eol

    def skip_full_line_star_comment(s: str, i: int) -> int:
        # Assumes s[i] == '*' and it's at BOL; returns index at end-of-line
        eol = s.find('\n', i)
        return len(s) if eol == -1 else eol

    def find_statement_period(s: str, start: int) -> int:
        # Returns the index of the '.' that terminates the ABAP statement starting at 'start'
        i = start
        n = len(s)
        in_sq = in_bt = in_tpl = False
        while i < n:
            c = s[i]
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    i = skip_line_comment(s, i)
                    continue
                if c == '*':
                    if i == 0 or s[i-1] == '\n':
                        i = skip_full_line_star_comment(s, i)
                        continue
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
                if c == '.':
                    return i
                i += 1
            else:
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            i += 2
                            continue
                        in_sq = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            i += 2
                            continue
                        in_bt = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            i += 2
                            continue
                        in_tpl = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
        return -1

    def find_kw(s: str, kw: str, start: int = 0) -> int:
        # Finds next occurrence of keyword outside strings/comments with word boundaries
        i = start
        n = len(s)
        in_sq = in_bt = in_tpl = False
        while i < n:
            c = s[i]
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    i = skip_line_comment(s, i) + 1
                    continue
                if c == '*':
                    if i == 0 or s[i-1] == '\n':
                        i = skip_full_line_star_comment(s, i) + 1
                        continue
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
                if match_kw_at(s, i, kw):
                    return i
                i += 1
            else:
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            i += 2
                            continue
                        in_sq = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            i += 2
                            continue
                        in_bt = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            i += 2
                            continue
                        in_tpl = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
        return -1

    def at_statement_lead(s: str, pos: int) -> bool:
        # True if 'pos' is the first non-space/tab character of its line and that line isn't a '*' comment line
        ls = s.rfind('\n', 0, pos)
        ls = 0 if ls == -1 else ls + 1
        k = ls
        while k < pos and s[k] in (' ', '\t'):
            k += 1
        if k < len(s) and s[k] == '*':
            return False
        return k == pos

    def next_executable_line_start(s: str, start: int) -> int:
        # Returns index of first character of the next non-empty, non-comment line starting at 'start'
        i = start
        n = len(s)
        while i < n:
            # move to line start
            if i == 0 or s[i-1] == '\n':
                # skip blank
                j = i
                while j < n and s[j] in (' ', '\t'):
                    j += 1
                if j >= n:
                    return n
                if s[j] == '\n':
                    i = j + 1
                    continue
                # skip full-line '*' comment
                if s[j] == '*':
                    i = skip_full_line_star_comment(s, j) + 1
                    continue
                # skip inline-quote comment-only line
                if s[j] == '"':
                    i = skip_line_comment(s, j) + 1
                    continue
                return j
            i += 1
        return n

    # ----------------- Helpers to analyze SELECT statement -----------------

    fae_re = re.compile(r'(?is)\bfor\s+all\s+entries\b')
    order_by_re = re.compile(r'(?is)\border\s+by\b')  # not directly used but kept for completeness

    # Extract the target internal table for INTO/APPENDING TABLE forms
    target_tbl_re = re.compile(
        r'''(?isx)
            \b(?:into|appending)\s+
            (?:corresponding\s+fields\s+of\s+)?    # optional 'CORRESPONDING FIELDS OF'
            (?:table\s+)?                           # optional 'TABLE'
            (?:
                @data\s*\(\s*(?P<t1>[A-Za-z_]\w*)\s*\)   # @DATA(name)
                |
                @?(?P<t2>[A-Za-z_]\w*)                   # or possibly @name or plain name
            )
        '''
    )

    def extract_target_table(stmt: str) -> str | None:
        m = target_tbl_re.search(stmt)
        if not m:
            return None
        t = m.group('t1') or m.group('t2')
        return t

    def extract_select_list(stmt: str) -> str:
        # stmt is the full SELECT statement without trailing period
        sel_idx = find_kw(stmt, 'select', 0)
        if sel_idx == -1:
            return ''
        i = sel_idx + 6
        n = len(stmt)
        while i < n and stmt[i].isspace():
            i += 1
        from_idx = find_kw(stmt, 'from', i)
        if from_idx == -1:
            return ''
        return stmt[i:from_idx].strip()

    def split_fields(field_segment: str) -> list[str]:
        """
        Split SELECT list into usable component names:
          - returns ['*'] for '*' or dynamic lists like '(...)'
          - prefers alias after 'AS' if present
          - transforms a~field to field
          - drops complex expressions without alias
        """
        s = field_segment.strip()
        if not s:
            return []
        # handle DISTINCT
        if s.lower().startswith('distinct'):
            s = s[8:].lstrip()
        # trivial star or dynamic list "(...)"
        if s == '*' or s.startswith('('):
            return ['*']

        # Tokenize respecting parentheses, quotes, templates; split on commas at depth 0
        items = []
        buf = []
        depth = 0
        i = 0
        n = len(s)
        in_sq = in_bt = in_tpl = False
        while i < n:
            c = s[i]
            if not (in_sq or in_bt or in_tpl):
                if c == "'":
                    in_sq = True
                    buf.append(c); i += 1; continue
                if c == '`':
                    in_bt = True
                    buf.append(c); i += 1; continue
                if c == '|':
                    in_tpl = True
                    buf.append(c); i += 1; continue
                if c == '(':
                    depth += 1; buf.append(c); i += 1; continue
                if c == ')':
                    depth = max(0, depth - 1); buf.append(c); i += 1; continue
                if depth == 0 and c == ',':
                    item = ''.join(buf).strip()
                    if item:
                        items.append(item)
                    buf = []
                    i += 1
                    continue
                buf.append(c); i += 1
            else:
                # inside string/template
                buf.append(c)
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            buf.append(s[i+1]); i += 2; continue
                        in_sq = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            buf.append(s[i+1]); i += 2; continue
                        in_bt = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            buf.append(s[i+1]); i += 2; continue
                        in_tpl = False
                    else:
                        i += 1
                        continue
                    i += 1
                    continue
        last = ''.join(buf).strip()
        if last:
            items.append(last)

        # If there were no commas, items may still contain space-separated tokens. Split conservatively.
        if ',' not in field_segment:
            # Break by whitespace into candidates; keep 'AS alias' together
            tokens = s.split()
            # Reconstruct items by splitting when a token looks like a field-reference or alias boundary
            items = []
            k = 0
            while k < len(tokens):
                if tokens[k].lower() == 'as' and k + 1 < len(tokens):
                    if items:
                        items.append(tokens[k-1] + ' AS ' + tokens[k+1])
                    else:
                        items.append('AS ' + tokens[k+1])
                    k += 2
                else:
                    items.append(tokens[k])
                    k += 1

        # Normalize each item to a usable component name
        out_fields = []
        for it in items:
            t = it.strip()
            if not t:
                continue
            # Remove surrounding parentheses if trivial
            if t.startswith('(') and t.endswith(')'):
                inner = t[1:-1].strip()
                if inner:
                    t = inner
            # Check alias
            m_as = re.search(r'(?is)\bas\b', t)
            if m_as:
                alias = t[m_as.end():].strip()
                if alias:
                    alias = alias.split()[0]
                    alias = alias.rstrip(',').strip()
                    if alias:
                        out_fields.append(alias)
                        continue
            # Remove qualifier a~field -> field
            if '~' in t:
                t = t.split('~')[-1].strip()
            # Remove trailing commas
            if t.endswith(','):
                t = t[:-1].strip()
            # If function/expression without alias (contains '('), skip
            if '(' in t or ')' in t:
                continue
            # Exclude keywords
            if t.lower() in ('distinct',):
                continue
            # Clean leading host var marker
            t = re.sub(r'^[@]+', '', t)
            # Accept identifier-like tokens only
            if re.match(r'^[A-Za-z_]\w*$', t):
                out_fields.append(t)

        # Deduplicate preserving order
        seen = set()
        res = []
        for f in out_fields:
            key = f.lower()
            if key not in seen:
                seen.add(key)
                res.append(f)
        return res if res else []

    def has_for_all_entries(stmt: str) -> bool:
        return fae_re.search(stmt) is not None

    def is_sort_immediately_next_for_target(s: str, period_pos: int, target: str) -> bool:
        start = next_executable_line_start(s, period_pos + 1)
        if start >= len(s):
            return False
        # Verify line starts with 'SORT <target>' ignoring case
        line_end = s.find('\n', start)
        line = s[start:] if line_end == -1 else s[start:line_end]
        # Remove inline comment
        q = line.find('"')
        if q != -1:
            line = line[:q]
        line = line.strip()
        m = re.match(r'(?is)^sort\s+([A-Za-z_]\w*)\b', line)
        if not m:
            return False
        return m.group(1).lower() == target.lower()

    def get_line_indent_before(pos: int) -> str:
        ls = code.rfind('\n', 0, pos)
        ls = 0 if ls == -1 else ls + 1
        k = ls
        indent = []
        while k < pos and code[k] in (' ', '\t'):
            indent.append(code[k]); k += 1
        return ''.join(indent)

    # ----------------- Main scanning loop -----------------

    out_parts = []
    i = 0
    n = len(code)

    while i < n:
        # Find next "select" token at statement lead, outside strings/comments
        scan = i
        in_sq = in_bt = in_tpl = False
        sel_pos = -1
        while scan < n:
            c = code[scan]
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    scan = skip_line_comment(code, scan)
                    if scan < n: scan += 1
                    continue
                if c == '*':
                    if scan == 0 or code[scan-1] == '\n':
                        scan = skip_full_line_star_comment(code, scan)
                        if scan < n: scan += 1
                        continue
                if c == "'":
                    in_sq = True; scan += 1; continue
                if c == '`':
                    in_bt = True; scan += 1; continue
                if c == '|':
                    in_tpl = True; scan += 1; continue
                if code[scan:scan+6].lower() == 'select' and (scan+6 == n or not is_word_char(code[scan+6])) and at_statement_lead(code, scan):
                    sel_pos = scan
                    break
                scan += 1
            else:
                # Ensure we always advance inside string/template blocks to avoid infinite loops
                if in_sq:
                    if c == "'":
                        if scan + 1 < n and code[scan+1] == "'":
                            scan += 2
                            continue
                        in_sq = False
                    else:
                        scan += 1
                        continue
                    scan += 1
                    continue
                if in_bt:
                    if c == '`':
                        if scan + 1 < n and code[scan+1] == '`':
                            scan += 2
                            continue
                        in_bt = False
                    else:
                        scan += 1
                        continue
                    scan += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if scan + 1 < n and code[scan+1] == '|':
                            scan += 2
                            continue
                        in_tpl = False
                    else:
                        scan += 1
                        continue
                    scan += 1
                    continue

        if sel_pos == -1:
            out_parts.append(code[i:])
            break

        # Append content before SELECT as-is
        out_parts.append(code[i:sel_pos])

        # Determine end of statement
        period_pos = find_statement_period(code, sel_pos)
        if period_pos == -1:
            # malformed; append remainder and stop
            out_parts.append(code[sel_pos:])
            break

        stmt = code[sel_pos:period_pos]  # without '.'

        # Condition: must have FOR ALL ENTRIES
        if not has_for_all_entries(stmt):
            # no change
            out_parts.append(code[sel_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # Determine target internal table
        target = extract_target_table(stmt)
        if not target:
            # Could not determine target table reliably; do not modify
            out_parts.append(code[sel_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # If next executable statement is already SORT <target>, skip
        if is_sort_immediately_next_for_target(code, period_pos, target):
            out_parts.append(code[sel_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # Build fields list from SELECT list
        select_list = extract_select_list(stmt)
        fields = split_fields(select_list)

        # Compose SORT statement
        indent = get_line_indent_before(sel_pos)
        if not fields or fields == ['*'] or any(f.strip() == '*' for f in fields):
            sort_stmt = f"{indent}SORT {target}."
        else:
            # ABAP SORT uses space-separated fields: BY f1 f2 f3
            sort_stmt = f"{indent}SORT {target} BY " + ' '.join(fields) + '.'

        # Insert: SELECT... . <newline> SORT ... <newline> " PwC tag
        insertion = '\n' + sort_stmt + '\n' + indent + pwc_tag_line

        out_parts.append(code[sel_pos:period_pos + 1] + insertion)

        # Continue after original period
        i = period_pos + 1

    return ''.join(out_parts)