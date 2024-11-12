import json
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer

def print_pretty_json(data):
    formatted_json = json.dumps(data, indent=2)
    colored_json = highlight(formatted_json, JsonLexer(), TerminalFormatter())
    print(colored_json)
