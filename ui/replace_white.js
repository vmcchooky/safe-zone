const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = path.join(dir, file);
        const stat = fs.statSync(file);
        if (stat && stat.isDirectory() && !file.includes('node_modules') && !file.includes('.git') && !file.includes('dist')) {
            results = results.concat(walk(file));
        } else if (file.endsWith('.tsx') || file.endsWith('.ts') || file.endsWith('.css') || file.endsWith('.svg')) {
            results.push(file);
        }
    });
    return results;
}

const files = walk('d:\\Quorix\\services\\safe-zone\\ui');

files.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    let original = content;

    content = content.replace(/\bbg-white\b/g, 'bg-slate-50');
    content = content.replace(/\bborder-white\b/g, 'border-slate-50');
    content = content.replace(/\btext-white\b/g, 'text-slate-50');
    content = content.replace(/#ffffff/gi, '#f8fafc');
    content = content.replace(/#fff\b/gi, '#f8fafc');
    content = content.replace(/fill="white"/gi, 'fill="#f8fafc"');
    content = content.replace(/stroke="white"/gi, 'stroke="#f8fafc"');
    content = content.replace(/color:\s*white\b/gi, 'color: #f8fafc');
    content = content.replace(/backgroundColor:\s*'white'/gi, "backgroundColor: '#f8fafc'");
    content = content.replace(/color:\s*'white'/gi, "color: '#f8fafc'");

    if (content !== original) {
        fs.writeFileSync(file, content, 'utf8');
        console.log('Updated', file);
    }
});
