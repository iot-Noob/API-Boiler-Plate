from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine
from App.GetEnvDate import db_name, db_path
import os

try:
    mp = os.path.join(db_path, db_name)
    
   
    if not os.path.exists(db_path):
        os.makedirs(db_path)
 
    engine = create_engine(
        f"sqlite:///{mp}", 
        
        pool_size=5, 
        max_overflow=9,   
 
    )
 
    Session = sessionmaker(bind=engine)
    session = Session()
     
    Base = declarative_base()
    
except Exception as e:
    print(f"Error connecting to the database: {e}")
