import os

# fix resolver_test.go
rt = "internal/dns/resolver/resolver_test.go"
if os.path.exists(rt):
    with open(rt, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace("package main", "package resolver")
    with open(rt, "w", encoding="utf-8") as f:
        f.write(content)

# fix sqlite_test.go
st = "internal/store/sqlite_test.go"
if os.path.exists(st):
    with open(st, "r", encoding="utf-8") as f:
        content = f.read()
    
    content = content.replace("db.QueryRecent(context.Background(), context.Background(),", "db.QueryRecent(context.Background(),")
    content = content.replace("db.GetGroupByName(context.Background(), context.Background(),", "db.GetGroupByName(context.Background(),")
    content = content.replace("db.GetGroupForClient(context.Background(), context.Background(),", "db.GetGroupForClient(context.Background(),")
    content = content.replace("db.GetEffectiveOverride(context.Background(), context.Background(),", "db.GetEffectiveOverride(context.Background(),")
    
    with open(st, "w", encoding="utf-8") as f:
        f.write(content)
