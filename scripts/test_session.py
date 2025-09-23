from config import get_sql_session
from sqlalchemy import text

with get_sql_session() as s:
    print("DB:", s.bind.engine.url)
    print("Users:", s.execute(text('SELECT COUNT(*) FROM [user]')).scalar())