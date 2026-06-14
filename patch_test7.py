import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

content = re.sub(r'Config: Config\{[^\}]*?\}\n', r'Config: Config{},\n', content)

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
