"""Terminal interaction provider: four-choice prompts over stdin/stdout."""
from .base import InteractionProvider


class TerminalProvider(InteractionProvider):
    """Terminal interaction: four-choice prompts + notifications (ignores channel)."""

    def ask_four(self, question: str, options: list[str], *, channel: str = "") -> str:
        """Print the question and options, wait for a 1-N choice.

        Args:
            question: prompt text.
            options: option list (e.g. ["add to whitelist", "allow once", "deny once", "add to blacklist"]).
            channel: ignored (terminal is the channel).

        Returns:
            The chosen option text.
        """
        print(question, flush=True)
        for i, opt in enumerate(options, 1):
            print(f"  [{i}] {opt}", flush=True)
        while True:
            try:
                raw = input(f"Choose (1-{len(options)}): ").strip()
                idx = int(raw)
                if 1 <= idx <= len(options):
                    return options[idx - 1]
            except (ValueError, EOFError, KeyboardInterrupt):
                pass
            print("Invalid choice, try again", flush=True)

    def notify(self, content: str, target: str = "", *, channel: str = "") -> str:
        """Send a notification to the terminal."""
        print(f"[{target or 'terminal'}] {content}", flush=True)
        return content
