# Golden dataset

Each `*.json` file in this directory is one labelled case used by the
`bounty-agent eval` command and the `test_eval.py` test suite.

Schema (validated by `bounty_agent.eval.dataset.GoldenCase`):

```json
{
  "id": "unique-string",
  "description": "What this case demonstrates.",
  "category": "sql_injection | xss | path_traversal | none",
  "url": "https://example.com/api/search?q=test",
  "payload": "' OR '1'='1",
  "response": {
    "status_code": 200,
    "headers": {"content-type": "text/html"},
    "body": "..."
  },
  "expected": "tp" | "fp"
}
```

- `tp` (true positive): the analyzer should fire for this case.
- `fp` (false positive): the analyzer should *not* fire. Used to make
  sure heuristics do not over-trigger on benign responses.

Add a new case by dropping a JSON file here; the eval harness picks it
up automatically.
