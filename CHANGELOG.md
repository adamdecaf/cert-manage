## 0.2.0 (Unreleased)

BREAKING CHANGES

- Performing a whitelist without a backup now fails [#53](https://github.com/adamdecaf/cert-manage/issues/53)

FEATURES

- **Support YAML whitelists as the default**
- Import browser history from Safari
- Add support for whitelisting based on CA country
- Use Chromium's certificate blacklist to never whitelist certificates
- Support whitelist generation from "top N domains" csv files
- Better browser import across platforms

IMPROVEMENTS

- **Whitelist generation is faster**
- Improve printed certificate names
- Better command help output
- Fix Darwin/OSX support for adding certificates
- Removed SHA1 output from `-format short` (default format)
- Create directories with tighter permissions
- Web certificate listing improvements
   - Minor colorization to the output
   - Sort certificates by Subject in web ui

BUG FIXES

- Make sure known Apple certificates are always restored
- Ensure certificates are deduplicated when accumulating them

BUILD

- Go 1.10 is required to build and test
- Run tests on windows for PR's

## 0.1.0 (2018-02-13)

- Initial release
