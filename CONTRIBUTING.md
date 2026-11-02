# Contributing

Focused changes that improve correctness, evidence quality and analyst usability are welcome.

1. Describe the problem in an issue using synthetic or sanitized examples.
2. Make a branch and keep changes focused.
3. Run `python -m unittest discover -s tests -v` and `node --check web/app.js` when JavaScript changes.
4. For interface changes, verify imports, filtering, workflow persistence, export and error messages in a local browser.
5. Explain the problem, resulting behavior, checks performed and remaining limits in a pull request.

Never commit production asset lists, notes, databases, exports or credentials. Dataset adapters must document field semantics, units, applicability assumptions and redistribution rights. Changes to scoring must include explicit policy-version and interpretation updates. The activity log is not a compliance audit record.

## Update your local clone

```powershell
git pull --ff-only
git switch -c improve-workflow
py -m unittest discover -s tests -v
git status
git diff
git add .
git commit -m "Describe the concrete change"
git push -u origin improve-workflow
```

Then open a pull request. Use `python3` instead of `py` on Linux/macOS.
