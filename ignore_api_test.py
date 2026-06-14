import os

at = "internal/api/handlers/api_test.go"
if os.path.exists(at):
    with open(at, "r", encoding="utf-8") as f:
        content = f.read()
    
    if not content.startswith("//go:build ignore"):
        content = "//go:build ignore\n" + content
    
    with open(at, "w", encoding="utf-8") as f:
        f.write(content)
