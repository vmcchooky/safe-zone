import os

# fix api_test.go
at = "internal/api/handlers/api_test.go"
if os.path.exists(at):
    with open(at, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace("api := &Handler{Config: Config{},\n\t\n\trecorder := httptest.NewRecorder()", "api := &Handler{Config: Config{}}\n\t\n\trecorder := httptest.NewRecorder()")
    content = content.replace("api := &Handler{Config: Config{},\n\trecorder := httptest.NewRecorder()", "api := &Handler{Config: Config{}}\n\trecorder := httptest.NewRecorder()")
    # Just generic replace:
    import re
    content = re.sub(r'api := &Handler\{Config: Config\{\},\s*recorder := httptest.NewRecorder\(\)', 'api := &Handler{Config: Config{}}\n\trecorder := httptest.NewRecorder()', content)
    with open(at, "w", encoding="utf-8") as f:
        f.write(content)

# fix sqlite_test.go
st = "internal/store/sqlite_test.go"
if os.path.exists(st):
    with open(st, "r", encoding="utf-8") as f:
        content = f.read()
    
    content = content.replace("db.GetWhoisCache(context.Background(), context.Background(),", "db.GetWhoisCache(context.Background(),")
    
    with open(st, "w", encoding="utf-8") as f:
        f.write(content)
