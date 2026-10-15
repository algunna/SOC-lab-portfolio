"""Offline Windows PowerShell host-flag heuristic; never execute/decode input.

Double-quote/backslash grouping for process command-line text, not a PowerShell
language parser. Only inspect flags before explicit Command/File boundaries.
"""
SWITCH_PREFIXES = '-/\u2013\u2014\u2015'


def tokens(command):
    """Group double-quoted argv fragments, including escaped quote/backslashes.

    Single quotes are literal in Windows native command-line text. Unbalanced
    quotes group to end, as a best-effort heuristic on possibly truncated logs.
    """
    result, current = [], []
    quoted = active = False
    index = 0
    while index < len(command):
        char = command[index]
        if char in ' \t\r\n' and not quoted:
            if active:
                result.append(''.join(current))
                current, active = [], False
            index += 1
            continue
        active = True
        if char == '\\':
            start = index
            while index < len(command) and command[index] == '\\':
                index += 1
            count = index - start
            if index < len(command) and command[index] == '"':
                current.extend('\\' * (count // 2))
                if count % 2:
                    current.append('"')
                    index += 1
                    continue
                # An even backslash run leaves the quote to the grouping rule.
            else:
                current.extend('\\' * count)
                continue
            char = command[index]
        if char == '"':
            if quoted and index + 1 < len(command) and command[index + 1] == '"':
                current.append('"')
                index += 2
                continue
            quoted = not quoted
        else:
            current.append(char)
        index += 1
    if active:
        result.append(''.join(current))
    return result


def indicators(command_line):
    if not isinstance(command_line, str):
        return []
    argv = [part.lower() for part in tokens(command_line)]
    found = set()
    for index, token in enumerate(argv):
        if not token or token[0] not in SWITCH_PREFIXES:
            continue
        name = token[1:]
        if name and ('command'.startswith(name) or 'file'.startswith(name)):
            break
        # pwsh's CommandWithArgs consumes the following command/arguments too.
        if name == 'cwa' or (len(name) >= 8 and 'commandwithargs'.startswith(name)):
            break
        following = argv[index + 1] if index + 1 < len(argv) else ''
        if name in ('e', 'ec') or (len(name) >= 2 and 'encodedcommand'.startswith(name)):
            found.add('encoded command')
        elif (name == 'ep' or (len(name) >= 2 and 'executionpolicy'.startswith(name))) and following == 'bypass':
            found.add('execution policy bypass')
        elif name and 'windowstyle'.startswith(name) and following in ('hidden', '1'):
            found.add('hidden window')
    return sorted(found)
