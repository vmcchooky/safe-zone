import sys
import glob
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    methods = [
        'QueryRecent', 'GetGroupByName', 'GetGroupForClient', 'GetEffectiveOverride',
        'SetWhoisCache', 'GetWhoisCache', 'SeedDefaultBrands'
    ]

    out = []
    func_pattern = re.compile(r'func\s+[^{]+\{', re.MULTILINE)
    matches = list(func_pattern.finditer(content))
    
    if len(matches) == 0:
        for m in methods:
            content = content.replace(f'db.{m}(', f'db.{m}(context.Background(), ')
            content = content.replace(f'storeDB.{m}(', f'storeDB.{m}(context.Background(), ')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return

    for i, match in enumerate(matches):
        if i == 0:
            out.append(content[:match.start()])
            
        start = match.end()
        end = matches[i+1].start() if i+1 < len(matches) else len(content)
        
        sig = match.group(0)
        body = content[start:end]
        
        ctx_val = 'context.Background()'
            
        for m in methods:
            body = body.replace(f'db.{m}(', f'db.{m}({ctx_val}, ')
            body = body.replace(f'storeDB.{m}(', f'storeDB.{m}({ctx_val}, ')
            
        out.append(sig)
        out.append(body)

    # ensure context import
    result = "".join(out)
    if 'context.Background()' in result and '"context"' not in result:
        result = result.replace('import (', 'import (\n\t"context"')
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result)

if __name__ == "__main__":
    for filepath in glob.glob('**/*_test.go', recursive=True):
        process_file(filepath)
