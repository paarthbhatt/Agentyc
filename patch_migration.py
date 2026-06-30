import glob
import os

files = glob.glob('backend/alembic/versions/*_initial.py')
if files:
    f_name = files[0]
    with open(f_name, 'r+') as f:
        content = f.read()
        f.seek(0)
        f.write(content.replace('import sqlalchemy as sa', 'import sqlalchemy as sa\nimport app.models'))
        f.truncate()
