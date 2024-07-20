import sqlite3
from App.GetEnvDate import db_name, db_path
from App.LoggingInit import *
import os

class DatabaseManager:
    def __init__(self):
        self.cursor = None
        self.connect = None
        self.path = None

    def connect_db(self):
        try:
            self.update_path()
            self.connect = sqlite3.connect(self.path)
            self.cursor = self.connect.cursor()
            logging.info(f"Connected to the database at {self.path}")
        except Exception as e:
            logging.error(f"Error connecting to the database due to {e}")

    def get_cursor(self):
        return self.cursor
    
    def get_connect(self):
        return self.connect
    
    def close_connection(self):
        if self.cursor is not None:
            self.cursor.close()
        if self.connect is not None:
            self.connect.close()
        self.cursor = None
        self.connect = None
        logging.info("Database connection closed")

    def update_path(self):
        if db_path and not os.path.exists(db_path):
            os.mkdir(db_path)
        if db_path and db_name:
            self.path = os.path.join(db_path, db_name)
        elif db_name:
            self.path = db_name
        else:
            self.path = "talha_db.db"