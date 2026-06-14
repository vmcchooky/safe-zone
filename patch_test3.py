import re

test_path = "internal/api/handlers/api_test.go"
with open(test_path, "r", encoding="utf-8") as f:
    content = f.read()

struct_regex = r'type statusResponse struct \{.*?\n\}\n'
match = re.search(struct_regex, content, re.DOTALL)
if match:
    struct_str = match.group(0)
    content = content.replace(struct_str, '')
    content += "\n" + struct_str

with open(test_path, "w", encoding="utf-8") as f:
    f.write(content)
