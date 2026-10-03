"""Encode cgo argument lists using Go cmd/internal/quoted.Join semantics."""


def join(arguments):
    fields = []
    for argument in arguments:
        if not any(c in argument for c in " \t\n\r'\""):
            fields.append(argument)
        elif "'" not in argument:
            fields.append("'" + argument + "'")
        elif '"' not in argument:
            fields.append('"' + argument + '"')
        else:
            raise ValueError('cgo argument contains both single and double quotes and cannot be encoded')
    return ' '.join(fields)
