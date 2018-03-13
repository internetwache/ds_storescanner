.DS_Store Scanner
==================

This is a tool written in Go that was used for [Scanning the Alexa top 1M for .DS_Store files](https://en.internetwache.org/scanning-the-alexa-top-1m-for-ds-store-files-12-03-2018/).

# Usage

```
./main --help
Usage of ./main:
  -c    Send HEAD request and show status code. Implies -l
  -d int
        Maximum recursion depth (default 7)
  -e    Preprend the URL to found files. Implies -l
  -i string
        Path to domain list
  -l    Parse .DS_Store and list files
  -q int
        Timeout in seconds (default 10)
  -r    Recursively scan directories for .DS_Store.
  -s    Use SSL (HTTPS) connection
  -t int
        Number of concurrent threads (default 10)
  -v    Verbose output (errors)
```

# License

Released under MIT. See LICENSE.md