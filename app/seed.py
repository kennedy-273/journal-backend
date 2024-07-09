from models import db, User, Journal
from sqlalchemy import text
from app import app

def execute_sql(sql):
    """Execute raw SQL"""
    with db.engine.begin() as connection:
        connection.execute(text(sql))

if __name__ == '__main__':
    with app.app_context():
        print('Clearing database...')
        execute_sql('TRUNCATE TABLE users, journals RESTART IDENTITY CASCADE')
        print('Database cleared!')