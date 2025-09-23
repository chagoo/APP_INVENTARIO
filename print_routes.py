from inventario import create_app

app = create_app({'TESTING': True})
print('RUTAS REGISTRADAS:')
for r in sorted(app.url_map.iter_rules(), key=lambda x: x.rule):
    methods = ','.join(sorted(m for m in r.methods if m not in {'HEAD','OPTIONS'}))
    print(f"{r.rule:40s} -> {methods}")
