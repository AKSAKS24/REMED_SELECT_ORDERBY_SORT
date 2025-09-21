# app/read_statment.py

import re
from datetime import date

def process_read(code: str) -> str:
    """
    Remediate ABAP READ TABLE statements according to rules:
      1) Detect each READ TABLE statement (single- or multi-line) that uses:
         - WITH KEY / WITH TABLE KEY / KEY
         - or INDEX
         and has no preceding SORT for the same table immediately before the READ
         (ignoring blank/comment-only lines).
      2) Insert a SORT statement for the internal table:
         - If READ is with INDEX -> insert: SORT <itab>.
         - If READ is with KEY/WITH TABLE KEY -> insert: SORT <itab> BY <field1> <field2> ...
           where fields come from left-hand sides in the KEY/COMPONENTS list (e.g., f1 = ..., f2 = ...).
           Note: tokens "WITH KEY"/"WITH TABLE KEY"/"COMPONENTS" themselves are NOT included as fields.
         - If fields cannot be reliably extracted (dynamic keys, etc.), fall back to: SORT <itab>.
      3) Insert SORT exactly before the READ statement and terminate it with a period.
      4) Add PwC tag only where a SORT was inserted, on its own line immediately after the SORT period:
         " Added By Pwc YYYY-MM-DD

    Robustness:
      - Ignores commented text:
        * full-line comments starting with '*' at column 1
        * inline comments starting with double quote "
      - Skips string literals: '...', `...`, and string templates |...|
      - Detects READ TABLE anywhere on a line.
      - Supports itab names as identifiers or field-symbols: name or <fsname>.

    Returns modified source as a single string.
    """

    pwc_tag_line = f'" Added By Pwc {date.today().isoformat()}\n'

    # ----------------- Lexical utilities -----------------

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
        # Assumes s[i] == '*' at BOL
        eol = s.find('\n', i)
        return len(s) if eol == -1 else eol

    def find_statement_period(s: str, start: int) -> int:
        # Returns index of '.' that terminates the ABAP statement starting at 'start'
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
                    in_sq = True; i += 1; continue
                if c == '`':
                    in_bt = True; i += 1; continue
                if c == '|':
                    in_tpl = True; i += 1; continue
                if c == '.':
                    return i
                i += 1
            else:
                # inside string/template
                if in_sq:
                    if c == "'":
                        if i + 1 < n and s[i+1] == "'":
                            i += 2; continue
                        in_sq = False
                    i += 1; continue
                if in_bt:
                    if c == '`':
                        if i + 1 < n and s[i+1] == '`':
                            i += 2; continue
                        in_bt = False
                    i += 1; continue
                if in_tpl:
                    if c == '|':
                        if i + 1 < n and s[i+1] == '|':
                            i += 2; continue
                        in_tpl = False
                    i += 1; continue
        return -1

    def get_line_indent_before(pos: int) -> str:
        # Indentation of the line containing position 'pos'
        ls = code.rfind('\n', 0, pos)
        ls = 0 if ls == -1 else ls + 1
        k = ls
        indent = []
        while k < pos and code[k] in (' ', '\t'):
            indent.append(code[k]); k += 1
        return ''.join(indent)

    def prev_executable_line_start(s: str, pos: int) -> int:
        # Return the index of the first non-space char of the previous non-empty, non-comment line before 'pos'
        i = pos
        while i > 0:
            # move to start of current/previous line
            nl = s.rfind('\n', 0, i)
            if nl == -1:
                ls = 0
            else:
                ls = nl + 1
            # trim leading spaces/tabs
            k = ls
            while k < i and s[k] in (' ', '\t'):
                k += 1
            # If line is empty or comment-only, move further up
            if k >= i or (k < len(s) and s[k] in ('\n', '\r')):
                i = ls - 1 if ls > 0 else 0
                continue
            if s[k] == '*':
                i = ls - 1 if ls > 0 else 0
                continue
            if s[k] == '"':
                i = ls - 1 if ls > 0 else 0
                continue
            # Found a previous executable line's first non-space index
            return k
        return -1

    # ----------------- READ statement analysis -----------------

    # READ TABLE ... itab ...
    itab_re = re.compile(r'(?is)\bread\s+table\s+(?P<itab><[A-Za-z_]\w*>|[A-Za-z_]\w*)\b')

    # Determine if READ uses INDEX
    def read_has_index(stmt: str) -> bool:
        return re.search(r'(?is)\bindex\b', stmt) is not None

    # Determine if READ uses KEY / WITH KEY / WITH TABLE KEY
    def read_has_key(stmt: str) -> bool:
        return re.search(r'(?is)\b(?:with\s+table\s+key|with\s+key|table\s+key|key)\b', stmt) is not None

    # Extract internal table identifier/field-symbol from READ statement
    def extract_itab(stmt: str) -> str | None:
        m = itab_re.search(stmt)
        return m.group('itab') if m else None

    # Extract list of key field names to be used for SORT BY, based on the READ KEY clause.
    # Strategy:
    #   1) Locate KEY anchor:
    #        - prefer "COMPONENTS" part if present; else part right after "WITH TABLE KEY" / "WITH KEY" / "KEY"
    #   2) From that anchor to the end of the statement, collect all identifiers immediately before '='.
    #   3) Deduplicate preserving order; ignore obviously non-field tokens.
    #   4) If nothing extracted (dynamic components etc.), return [].
    def extract_key_fields(stmt: str) -> list[str]:
        lower = stmt.lower()

        # Find the first relevant KEY phrase after "read table <itab>"
        m_itab = itab_re.search(stmt)
        search_from = m_itab.end() if m_itab else 0

        # Look for 'with table key', 'with key', or bare 'key'
        m_key = (re.search(r'(?is)\bwith\s+table\s+key\b', stmt[search_from:]) or
                 re.search(r'(?is)\bwith\s+key\b', stmt[search_from:]) or
                 re.search(r'(?is)\btable\s+key\b', stmt[search_from:]) or
                 re.search(r'(?is)\bkey\b', stmt[search_from:]))

        if not m_key:
            return []

        key_start = search_from + m_key.end()

        # If 'COMPONENTS' follows, anchor after it
        m_comp = re.search(r'(?is)\bcomponents\b', stmt[key_start:])
        if m_comp:
            key_start = key_start + m_comp.end()

        # Substring containing assignments like f1 = ..., f2 = ...
        key_section = stmt[key_start:]

        # Collect identifiers immediately before '='
        # Accept identifiers of the form: name (letters/digits/_), and also 'table_line'
        candidates = re.findall(r'(?is)\b([A-Za-z_]\w*)\s*=', key_section)

        # Deduplicate preserving order
        fields = []
        seen = set()
        for f in candidates:
            fl = f.lower()
            # Filter out obvious non-fields if any
            if fl in ('with', 'table', 'key', 'components'):
                continue
            if fl not in seen:
                seen.add(fl)
                fields.append(f)

        return fields

    # Check if the immediately previous executable line starts with "SORT <itab>"
    def is_sort_immediately_before(s: str, read_pos: int, itab: str) -> bool:
        prev_start = prev_executable_line_start(s, read_pos)
        if prev_start == -1:
            return False
        line_end = s.find('\n', prev_start)
        line = s[prev_start:] if line_end == -1 else s[prev_start:line_end]
        # Remove inline comment if any
        q = line.find('"')
        if q != -1:
            line = line[:q]
        line = line.strip()
        # Match SORT for same itab (supports field-symbols like <fs>)
        m = re.match(r'(?is)^sort\s+(<\w+>|[A-Za-z_]\w*)\b', line)
        if not m:
            return False
        return m.group(1).lower() == itab.lower()

    # ----------------- Main processing loop -----------------

    out_parts = []
    i = 0
    n = len(code)

    while i < n:
        # Scan for next top-level "read table" outside strings/comments
        scan = i
        in_sq = in_bt = in_tpl = False
        read_pos = -1

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
                    in_sq = True; scan += 1; continue
                if c == '`':
                    in_bt = True; scan += 1; continue
                if c == '|':
                    in_tpl = True; scan += 1; continue
                # Possible READ TABLE
                if match_kw_at(code, scan, 'read'):
                    # after 'read', ensure next keyword 'table'
                    j = scan + 4
                    # skip spaces/tabs/newlines
                    while j < n and code[j] in (' ', '\t', '\r', '\n'):
                        j += 1
                    if match_kw_at(code, j, 'table'):
                        read_pos = scan
                        break
                scan += 1
            else:
                # inside string/template
                if in_sq:
                    if c == "'":
                        if scan + 1 < n and code[scan+1] == "'":
                            scan += 2; continue
                        in_sq = False
                    scan += 1; continue
                if in_bt:
                    if c == '`':
                        if scan + 1 < n and code[scan+1] == '`':
                            scan += 2; continue
                        in_bt = False
                    scan += 1; continue
                if in_tpl:
                    if c == '|':
                        if scan + 1 < n and code[scan+1] == '|':
                            scan += 2; continue
                        in_tpl = False
                    scan += 1; continue

        if read_pos == -1:
            out_parts.append(code[i:])
            break

        # Append everything before this READ as-is
        out_parts.append(code[i:read_pos])

        # Determine end of READ statement (the '.' terminator)
        period_pos = find_statement_period(code, read_pos)
        if period_pos == -1:
            # Malformed or unterminated; leave rest untouched
            out_parts.append(code[read_pos:])
            break

        # Extract the full READ statement text (without '.')
        read_stmt = code[read_pos:period_pos]
        itab = extract_itab(read_stmt)

        # If cannot determine the itab, do not modify
        if not itab:
            out_parts.append(code[read_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # Determine if READ uses INDEX or KEY
        has_index = read_has_index(read_stmt)
        has_key = read_has_key(read_stmt)

        # If neither INDEX nor KEY variants matched, skip
        if not (has_index or has_key):
            out_parts.append(code[read_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # If there's already a SORT <itab> immediately before this READ, do not insert another
        if is_sort_immediately_before(code, read_pos, itab):
            out_parts.append(code[read_pos:period_pos + 1])
            i = period_pos + 1
            continue

        # Build SORT statement based on variant
        indent = get_line_indent_before(read_pos)

        if has_index:
            sort_stmt = f"{indent}SORT {itab}."
        else:
            # KEY variant: extract fields
            fields = extract_key_fields(read_stmt)
            if fields:
                # ABAP SORT BY uses space-separated fields
                fields_unique = []
                seen = set()
                for f in fields:
                    fl = f.lower()
                    if fl not in seen:
                        seen.add(fl)
                        fields_unique.append(f)
                sort_stmt = f"{indent}SORT {itab} BY " + ' '.join(fields_unique) + '.'
            else:
                # Fallback if no fields resolvable (dynamic key etc.)
                sort_stmt = f"{indent}SORT {itab}."

        # Insert SORT before READ with PwC tag after the SORT period
        insertion = sort_stmt + "\n" + indent + pwc_tag_line

        out_parts.append(insertion)
        # Append the original READ statement and its terminating period
        out_parts.append(code[read_pos:period_pos + 1])

        # Advance past the READ statement
        i = period_pos + 1

    return ''.join(out_parts)