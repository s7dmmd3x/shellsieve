# shellsieve

Static analyzer for bash/zsh scripts that flags unsafe patterns and injection risks.

---

## Installation

```bash
pip install shellsieve
```

Or install from source:

```bash
git clone https://github.com/yourusername/shellsieve.git && cd shellsieve && pip install .
```

---

## Usage

Analyze a single script:

```bash
shellsieve check myscript.sh
```

Scan an entire directory:

```bash
shellsieve check ./scripts/
```

Example output:

```
myscript.sh:12  [HIGH]   Unquoted variable in command substitution: $USER_INPUT
myscript.sh:27  [MEDIUM] Use of eval with dynamic input
myscript.sh:43  [LOW]    Deprecated backtick syntax, prefer $()

3 issues found (1 high, 1 medium, 1 low)
```

Use `--format json` for machine-readable output:

```bash
shellsieve check myscript.sh --format json
```

---

## Checks Performed

- Unquoted variables susceptible to word splitting
- `eval` and `exec` with user-controlled input
- Command injection via unsafe `$()` or backtick usage
- Insecure use of `curl | bash` patterns
- Missing `set -euo pipefail` safeguards

---

## License

MIT © 2024 shellsieve contributors