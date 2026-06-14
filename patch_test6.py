import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

# Fix `missing ',' before newline` which is typically from:
# Config: Config{AdminAPIKey: "testkey"
# }
content = re.sub(r'Config: Config\{([^\}]*?)\n\t\}', r'Config: Config{\1},\n\t}', content)

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
