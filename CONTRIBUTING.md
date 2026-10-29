# Contributing to COCOSCANNER

Thanks for your interest in contributing.

1. Open an issue describing a bug or proposed improvement before large changes.
2. Fork the repository and create a focused branch.
3. Keep changes small and explain user-visible behavior in the README or HELP.md.
4. Run the regression tests before opening a pull request:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

5. Never commit PCAP files, private network details, credentials, API keys, or local `data/*.json` records.
6. Use packet captures and network scans only where you have authorization.

Pull requests should describe what changed, how it was tested, and any known limitations.
