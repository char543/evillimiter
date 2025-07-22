import re
import os
import atexit
import readline
import colorama
from . import shell

# Configure readline and history
HISTFILE = os.path.expanduser('~/.evillimiter_history')
HISTFILE_SIZE = 1000

# Configure readline behavior
readline.parse_and_bind('set enable-keypad on')
readline.parse_and_bind('set input-meta on')
readline.parse_and_bind('set convert-meta off')
readline.parse_and_bind('set output-meta on')
readline.parse_and_bind('set mark-directories on')
readline.parse_and_bind('set show-all-if-ambiguous on')
readline.parse_and_bind('set echo-control-characters off')
readline.parse_and_bind('set editing-mode emacs')  # Use emacs-style editing
readline.parse_and_bind('set horizontal-scroll-mode on')
readline.parse_and_bind('set completion-ignore-case on')

# Try to load history file
try:
    readline.read_history_file(HISTFILE)
    readline.set_history_length(HISTFILE_SIZE)
except FileNotFoundError:
    pass

# Save history on exit
atexit.register(readline.write_history_file, HISTFILE)

# Set up readline history
HISTFILE = os.path.expanduser('~/.evillimiter_history')
HISTFILE_SIZE = 1000

# Configure readline
readline.parse_and_bind('set enable-keypad on')
readline.parse_and_bind('set input-meta on')
readline.parse_and_bind('set convert-meta off')
readline.parse_and_bind('set output-meta on')
readline.parse_and_bind('set mark-directories on')
readline.parse_and_bind('set show-all-if-ambiguous on')
readline.parse_and_bind('set echo-control-characters off')

# Try to load history file
try:
    readline.read_history_file(HISTFILE)
    readline.set_history_length(HISTFILE_SIZE)
except FileNotFoundError:
    pass

# Save history on exit
atexit.register(readline.write_history_file, HISTFILE)


class IO(object):
    _ANSI_CSI_RE = re.compile('\001?\033\\[((?:\\d|;)*)([a-zA-Z])\002?') 

    Back = colorama.Back
    Fore = colorama.Fore
    Style = colorama.Style

    colorless = False

    @staticmethod
    def initialize(colorless=False):
        """
        Initializes console input and output.
        """
        IO.colorless = colorless
        if not colorless:
            colorama.init(autoreset=True)

    @staticmethod
    def print(text, end='\n', flush=False):
        """
        Writes a given string to the console.
        """
        if IO.colorless:
            text = IO._remove_colors(text)

        print(text, end=end, flush=flush)

    @staticmethod
    def ok(text, end='\n'):
        """
        Print a success status message
        """
        IO.print('{}OK{}   {}'.format(IO.Style.BRIGHT + IO.Fore.LIGHTGREEN_EX, IO.Style.RESET_ALL, text), end=end)

    @staticmethod
    def error(text):
        """
        Print an error status message
        """
        IO.print('{}ERR{}  {}'.format(IO.Style.BRIGHT + IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL, text))

    @staticmethod
    def spacer():
        """
        Prints a blank line for attraction purposes
        """
        IO.print('')

    @staticmethod
    def input(prompt):
        """
        Prompts the user for input with readline support.
        Handles color sequences properly and provides command history.
        """
        if IO.colorless:
            prompt = IO._remove_colors(prompt)

        # Handle color escape sequences properly
        # Wrap color sequences in \001 and \002 so readline knows to ignore them
        wrapped_prompt = ''
        last_end = 0
        for match in IO._ANSI_CSI_RE.finditer(prompt):
            start, end = match.span()
            wrapped_prompt += prompt[last_end:start]  # Add text before escape sequence
            wrapped_prompt += '\001' + prompt[start:end] + '\002'  # Wrap escape sequence
            last_end = end
        wrapped_prompt += prompt[last_end:]  # Add remaining text

        # Get input with history support
        try:
            line = input(wrapped_prompt)
            if line.strip():  # Only add non-empty lines to history
                readline.add_history(line)
            return line
        except EOFError:  # Ctrl+D
            print()
            return 'exit'
        except KeyboardInterrupt:  # Ctrl+C
            print()
            return 'exit'  # Make Ctrl+C exit like before

    @staticmethod
    def clear():
        """
        Clears the terminal screen
        """
        shell.execute('clear')

    @staticmethod
    def _remove_colors(text):
        edited = text

        for match in IO._ANSI_CSI_RE.finditer(text):
                s, e = match.span()
                edited = edited.replace(text[s:e], '')

        return edited
