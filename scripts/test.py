from config import get_sql_session
from sqlalchemy import text

@web_bp.route('/diag/db')
def diag_db():
    with get_sql_session() as s:
        users = s.execute(text('SELECT COUNT(*) FROM [user]')).scalar()
    return {'users': users}