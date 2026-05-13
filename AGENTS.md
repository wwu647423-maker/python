## Cursor Cloud specific instructions

This repository is a collection of standalone Python 3 beginner exercise scripts (with Chinese-language filenames). There is no package manager, no framework, no build system, and no test suite.

### Running scripts

Each `.py` file is self-contained and runs directly with `python3 <filename>`. Some scripts require interactive stdin input (e.g. `判断素数.py`, `银行存取钱.py`); pipe input when running non-interactively:

```
echo "12" | python3 "判断素数.py"
printf "TestUser\n1\n4\n" | python3 "银行存取钱.py"
```

### Notes

- No external dependencies — only the Python 3 standard library is used.
- No linter, formatter, or test framework is configured.
- Filenames contain Chinese characters; always quote them in shell commands.
