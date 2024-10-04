from App.SQL_Connector import session,Base,engine
from sqlalchemy import Column,Integer,VARCHAR,String,TEXT,Float,TIMESTAMP,DateTime,func,Boolean
from sqlalchemy.orm import relationship
class Users(Base):
    __tablename__ = "users"
    
    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(33), nullable=False, unique=True)
    email = Column(String(200), nullable=False, unique=True)
    password = Column(String(200), nullable=False)  
    profile_pic = Column(String(200), nullable=True)  
    user_role = Column(String(50), nullable=True)   
    disable = Column(Boolean, default=False, nullable=False)  

Base.metadata.create_all(engine)