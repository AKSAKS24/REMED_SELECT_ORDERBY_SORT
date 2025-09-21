# app/orderby.py

import re
from datetime import date

def process_orderby(code: str) -> str:
    """
    Remediate ABAP SELECT statements that:
      - do NOT contain "FOR ALL ENTRIES"
      - do NOT contain "ORDER BY"
    And then:
      - Add "ORDER BY <field list>" extracted from the SELECT list.
      - If the SELECT list is '*' or cannot be reliably extracted, use "ORDER BY PRIMARY KEY".
      - Insert ORDER BY after the WHERE clause (if present), otherwise before the terminating period.
      - Only modify real ABAP code (ignore commented or string content).
      - Add PwC tag as a new comment line directly above each modified SELECT:
        " Added By Pwc YYYY-MM-DD

    Supports:
      - Single- or multi-line statements
      - SELECT with or without JOINs
      - Space-separated or comma-separated field lists
      - Aliases (AS)
      - Aggregates and parentheses in the select list
      - Inline comments (") and full-line comments (*)
      - Strings: '...', `...`, |...|
    """

    pwc_tag_line = f'" Added By Pwc {date.today().isoformat()}\n'

    # --- Utilities for lexical scanning ------------------------------

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
        # Assumes s[i] == '"'
        eol = s.find('\n', i)
        return len(s) if eol == -1 else eol

    def skip_full_line_star_comment(s: str, i: int) -> int:
        # Assumes s[i] == '*' and it's at BOL
        eol = s.find('\n', i)
        return len(s) if eol == -1 else eol

    def find_statement_period(s: str, start: int) -> int:
        # Finds the position of the terminating '.' of the statement starting at 'start'
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
                    # full-line comment only at BOL
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
                continue
            # inside strings/templates
            if in_sq:
                if c == "'":
                    if i + 1 < n and s[i+1] == "'":
                        i += 2
                        continue
                    in_sq = False
                i += 1
                continue
            if in_bt:
                if c == '`':
                    if i + 1 < n and s[i+1] == '`':
                        i += 2
                        continue
                    in_bt = False
                i += 1
                continue
            if in_tpl:
                if c == '|':
                    if i + 1 < n and s[i+1] == '|':
                        i += 2
                        continue
                    in_tpl = False
                i += 1
                continue
        return -1

    def find_kw(s: str, kw: str, start: int = 0) -> int:
        # Finds next occurrence of keyword outside strings/comments
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
                continue
            else:
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            i += 2
                            continue
                        in_sq = False
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            i += 2
                            continue
                        in_bt = False
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            i += 2
                            continue
                        in_tpl = False
                    i += 1
                    continue
        return -1

    def find_phrase(s: str, phrase_re: re.Pattern, start: int = 0) -> int:
        # Find phrase (compiled regex) outside strings/comments
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
                m = phrase_re.search(s, i)
                if not m:
                    return -1
                # verify the match is not broken by entering string/comment
                # Since we step token-by-token above, if we found it, it's valid here.
                return m.start()
            else:
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            i += 2
                            continue
                        in_sq = False
                    i += 1
                    continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            i += 2
                            continue
                        in_bt = False
                    i += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            i += 2
                            continue
                        in_tpl = False
                    i += 1
                    continue
        return -1

    def at_statement_lead(s: str, pos: int) -> bool:
        # True if 'pos' is the first non-space/tab char of a statement line (ignoring leading spaces/tabs)
        # and not inside commented line.
        # Find line start
        ls = s.rfind('\n', 0, pos)
        ls = 0 if ls == -1 else ls + 1
        # If this line starts with '*', it's a comment
        k = ls
        while k < pos and s[k] in (' ', '\t'):
            k += 1
        if k < len(s) and s[k] == '*':
            return False
        # Also ensure we are not after a period on same line (i.e., multiple statements per line)
        # ABAP style is one statement per line; require 'pos' be the first token on the line
        return k == pos

    def normalize_spaces_preserve_newlines(text: str) -> str:
        # Collapse runs of spaces/tabs but keep newlines as-is
        def repl(m):
            s = m.group(0)
            return ' ' if '\n' not in s else s
        return re.sub(r'[ \t]+', repl, text)

    # --- Field extraction from SELECT list ---------------------------

    # Combined robust extract: from after 'select' to the 'from'
    def extract_select_list(stmt: str) -> str:
        # stmt is the full SELECT statement without trailing period
        sel_idx = find_kw(stmt, 'select', 0)
        if sel_idx == -1:
            return ''
        # skip 'select'
        i = sel_idx + 6
        n = len(stmt)
        # skip whitespace
        while i < n and stmt[i].isspace():
            i += 1
        # The 'from' delim
        from_idx = find_kw(stmt, 'from', i)
        if from_idx == -1:
            return ''
        return stmt[i:from_idx].strip()

    def split_fields(field_segment: str) -> list[str]:
        """
        Split field list into individual items:
          - supports comma-separated and whitespace-separated lists
          - respects parentheses (no split inside)
          - returns clean item strings (without trailing commas)
        """
        s = field_segment.strip()
        if not s:
            return []

        # If dynamic list "(...)" or star used as the only item
        if s == '*' or s.lower().startswith('('):
            return ['*']

        items = []
        buf = []
        depth = 0
        i = 0
        n = len(s)
        in_sq = in_bt = in_tpl = False
        while i < n:
            c = s[i]
            # string/template handling inside select list (rare but safe)
            if not (in_sq or in_bt or in_tpl):
                if c == "'":
                    in_sq = True
                    buf.append(c)
                    i += 1
                    continue
                if c == '`':
                    in_bt = True
                    buf.append(c)
                    i += 1
                    continue
                if c == '|':
                    in_tpl = True
                    buf.append(c)
                    i += 1
                    continue

                if c == '(':
                    depth += 1
                    buf.append(c)
                    i += 1
                    continue
                if c == ')':
                    depth = max(0, depth - 1)
                    buf.append(c)
                    i += 1
                    continue

                if depth == 0 and c == ',':
                    # end of an item
                    item = ''.join(buf).strip()
                    if item:
                        items.append(item)
                    buf = []
                    i += 1
                    continue

                # whitespace separates items if not using commas and outside parens
                if depth == 0 and c.isspace():
                    # collapse to single space inside item
                    if buf and buf[-1] != ' ':
                        buf.append(' ')
                    i += 1
                    continue

                buf.append(c)
                i += 1
                continue

            else:
                # inside quoted text
                if in_sq:
                    buf.append(c)
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            buf.append(s[i+1])
                            i += 2
                            continue
                        in_sq = False
                    i += 1
                    continue
                if in_bt:
                    buf.append(c)
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            buf.append(s[i+1])
                            i += 2
                            continue
                        in_bt = False
                    i += 1
                    continue
                if in_tpl:
                    buf.append(c)
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            buf.append(s[i+1])
                            i += 2
                            continue
                        in_tpl = False
                    i += 1
                    continue

        # flush last
        last = ''.join(buf).strip()
        if last:
            items.append(last)

        # If no commas and items are space-split, ensure we split properly:
        # items might still contain multiple items if commas absent and we kept single spaces
        # We'll split by spaces but try to keep "AS alias" grouped.
        final_items = []
        for it in items:
            # Split by spaces into tokens
            toks = [t for t in it.strip().split(' ') if t]
            if not toks:
                continue
            # Merge tokens into fields (whitespace-separated list)
            k = 0
            curr = []
            while k < len(toks):
                tok = toks[k]
                if tok.lower() == 'as' and curr:
                    # take alias (next token if any) as the field identifier
                    if k + 1 < len(toks):
                        # The alias becomes the defining field for ORDER BY
                        final_items.append(toks[k+1])
                        k += 2
                        curr = []
                        # any remaining tokens after alias start a new item
                        continue
                    else:
                        # trailing AS without alias - ignore
                        k += 1
                        continue
                elif tok.lower() in ('distinct',):
                    k += 1
                    continue
                else:
                    curr.append(tok)
                    # Heuristic: ABAP usually uses explicit list; if next token is a table-field like a~b,
                    # treat as separate item when curr already has one token
                    if len(curr) >= 1 and k + 1 < len(toks):
                        # peek: if next is a simple identifier-like token, we assume next item
                        nxt = toks[k+1]
                        # We'll close item here and continue
                        final_items.append(' '.join(curr))
                        curr = []
                    k += 1
            if curr:
                final_items.append(' '.join(curr))

        # If comma-separated, 'items' are already good; but they may contain "AS alias"
        if ',' in field_segment:
            final_items = []
            for it in items:
                # Detect " AS " outside parentheses
                # Simple split on ' as ' ignoring case
                m = re.search(r'(?i)\bas\b', it)
                if m:
                    # take alias (text after AS)
                    alias = it[m.end():].strip()
                    # If alias has trailing tokens, cut at first space
                    alias = alias.split()[0] if alias else ''
                    final_items.append(alias if alias else it[:m.start()].strip())
                else:
                    final_items.append(it.strip())

        # Clean up: remove empty and special keywords
        cleaned = []
        for x in final_items:
            x = x.strip()
            if not x:
                continue
            xl = x.lower()
            if xl in ('distinct',):
                continue
            cleaned.append(x)

        return cleaned

    # --- Clause boundary helpers ------------------------------------

    # For WHERE clause end, look for next clause keyword
    WHERE_TERMINATORS = [
        'group', 'having', 'order', 'into', 'appending', 'up', 'for', 'bypassing',
        'union', 'intersect', 'except', 'client', 'using', 'package'
    ]

    def find_next_any_kw(s: str, keywords: list[str], start: int) -> tuple[int, str | None]:
        best_idx = -1
        best_kw = None
        for kw in keywords:
            idx = find_kw(s, kw, start)
            if idx != -1 and (best_idx == -1 or idx < best_idx):
                best_idx = idx
                best_kw = kw
        return best_idx, best_kw

    # --- Decision helpers --------------------------------------------

    fae_re = re.compile(r'(?i)\bfor\s+all\s+entries\b')
    order_by_re = re.compile(r'(?i)\border\s+by\b')

    def has_for_all_entries(stmt: str) -> bool:
        return find_phrase(stmt, fae_re, 0) != -1

    def has_order_by(stmt: str) -> bool:
        return find_phrase(stmt, order_by_re, 0) != -1

    # --- Main processing loop ----------------------------------------

    out = []
    i = 0
    n = len(code)

    while i < n:
        # scan for next top-level 'select' that is at statement lead
        scan = i
        in_sq = in_bt = in_tpl = False
        sel_pos = -1

        while scan < n:
            c = code[scan]
            if not (in_sq or in_bt or in_tpl):
                if c == '"':
                    scan = skip_line_comment(code, scan)
                    if scan < n:
                        scan += 1
                    continue
                if c == '*':
                    if scan == 0 or code[scan-1] == '\n':
                        scan = skip_full_line_star_comment(code, scan)
                        if scan < n:
                            scan += 1
                        continue
                if c == "'":
                    in_sq = True
                    scan += 1
                    continue
                if c == '`':
                    in_bt = True
                    scan += 1
                    continue
                if c == '|':
                    in_tpl = True
                    scan += 1
                    continue
                if code[scan:scan+6].lower() == 'select' and (scan+6 == n or not is_word_char(code[scan+6])) and at_statement_lead(code, scan):
                    sel_pos = scan
                    break
                scan += 1
                continue
            else:
                if in_sq:
                    if c == "'":
                        if scan + 1 < n and code[scan+1] == "'":
                            scan += 2
                            continue
                        in_sq = False
                    scan += 1
                    continue
                if in_bt:
                    if c == '`':
                        if scan + 1 < n and code[scan+1] == '`':
                            scan += 2
                            continue
                        in_bt = False
                    scan += 1
                    continue
                if in_tpl:
                    if c == '|':
                        if scan + 1 < n and code[scan+1] == '|':
                            scan += 2
                            continue
                        in_tpl = False
                    scan += 1
                    continue

        if sel_pos == -1:
            out.append(code[i:])
            break

        # Append text before SELECT as-is
        out.append(code[i:sel_pos])

        # Find terminating period for this statement
        period = find_statement_period(code, sel_pos)
        if period == -1:
            # malformed; append rest and stop
            out.append(code[sel_pos:])
            break

        stmt = code[sel_pos:period]  # without '.'

        # Check skip conditions
        if has_for_all_entries(stmt) or has_order_by(stmt):
            # No change
            out.append(code[sel_pos:period+1])
            i = period + 1
            continue

        # Extract indent (for PWC tag)
        line_start = code.rfind('\n', 0, sel_pos)
        line_start = 0 if line_start == -1 else line_start + 1
        indent = ''
        k = line_start
        while k < sel_pos and code[k] in (' ', '\t'):
            indent += code[k]
            k += 1

        # Build ORDER BY list
        select_list = extract_select_list(stmt)
        fields = split_fields(select_list)

        use_primary_key = False
        if not fields or fields == ['*'] or any(f.strip() == '*' for f in fields):
            use_primary_key = True

        if use_primary_key:
            orderby_clause = ' ORDER BY PRIMARY KEY'
        else:
            # Clean items: remove residual noise tokens if any
            cleaned = []
            for f in fields:
                t = f.strip()
                if not t:
                    continue
                # Remove trailing commas if any
                if t.endswith(','):
                    t = t[:-1].strip()
                # If token contains ' AS ' pick alias (already handled but safe)
                m = re.search(r'(?i)\bas\b', t)
                if m:
                    alias = t[m.end():].strip().split()[0] if t[m.end():].strip() else ''
                    t = alias if alias else t[:m.start()].strip()
                # Remove parentheses around bare identifiers e.g., (col) -> col
                if t.startswith('(') and t.endswith(')'):
                    inner = t[1:-1].strip()
                    if re.match(r'^[A-Za-z_]\w*(~[A-Za-z_]\w*)?$', inner):
                        t = inner
                cleaned.append(t)
            # Deduplicate while preserving order
            seen = set()
            ordered = []
            for f in cleaned:
                key = f.lower()
                if key not in seen:
                    seen.add(key)
                    ordered.append(f)
            orderby_clause = ' ORDER BY ' + ', '.join(ordered if ordered else ['PRIMARY KEY'])

        # Decide insertion point: after WHERE clause if present, else before period
        where_idx = find_kw(stmt, 'where', 0)
        insert_pos_in_stmt = None
        if where_idx != -1:
            # End of WHERE clause is at next terminator or end of stmt
            search_start = where_idx + 5
            end_idx, _ = find_next_any_kw(stmt, WHERE_TERMINATORS, search_start)
            insert_pos_in_stmt = end_idx if end_idx != -1 else len(stmt)
        else:
            insert_pos_in_stmt = len(stmt)

        # Construct new statement
        left = stmt[:insert_pos_in_stmt].rstrip()
        right = stmt[insert_pos_in_stmt:].lstrip()
        new_stmt = f"{left}{orderby_clause}"
        if right:
            new_stmt = f"{new_stmt} {right}"

        new_stmt = normalize_spaces_preserve_newlines(new_stmt).strip()

        # Build replacement text with PwC tag
        replacement = indent + pwc_tag_line + new_stmt + '.'

        out.append(replacement)

        # Advance
        i = period + 1

    return ''.join(out)