import mysql.connector
from config import db_config

def get_db_connection():
    """Создание подключения к базе данных MySQL."""
    return mysql.connector.connect(**db_config)
