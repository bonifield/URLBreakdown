# URLBreakdown
splits a URL into individual components, unescapes arguments, and performs light calculations for manual or automated analysis

### Installation
```
pip install urlbreakdown
```

### Usage
**URLBreakdown("url", pguid=None, verbose=False)**
- default is just a URL, with no parent GUID, in non-verbose mode
	- include a parent GUID/UUID if generated in the script calling this module
	- verbose includes a simple character frequency map, and an additional array-of-nested-arrays of parameters
```
from urlbreakdown import URLBreakdown
u = URLBreakdown("https://search.yahoo.com/search?p=google&fr=yfp-t&ei=UTF-8&fp=1&blank1=&blank2=")
print(u.json)
#
# optional arguments pguid and verbose
#
u = URLBreakdown("https://search.yahoo.com/search?p=google&fr=yfp-t&ei=UTF-8&fp=1&blank1=&blank2=", pguid="1234-5678-9001", verbose=True)
```

### Available Attributes
```
json (string)
output (dictionary)
```

### Example Output (via test-ipv4mutate-usage-example.py)
```
{
  "@timestamp": "2021-04-28T19:46:38.144Z",
  "guid": "be9fc53e-04a1-4ec9-b382-5a3ef7704039",
  "url": {
    "full": "https://www.google.com/search?client=firefox-b-1-d&q=reddit&a=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E",
    "len": 104,
    "original": "https://www.google.com/search?client=firefox-b-1-d&q=reddit&a=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E",
    "dot_count_url": 2,
    "scheme": "https",
    "domain": "www.google.com",
    "dot_count_domain": 2,
    "query": "client=firefox-b-1-d&q=reddit&a=%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E",
    "query_len": 74,
    "path": "/search",
    "unquoted": {
      "query": "client=firefox-b-1-d&q=reddit&a=<script>alert(1);</script>",
      "query_len": 58
    },
    "parameters": {
      "keys": [
        "a",
        "q",
        "client"
      ],
      "values": [
        "reddit",
        "<script>alert(1)",
        "firefox-b-1-d",
        "<script>alert(1);</script>"
      ],
...
```
