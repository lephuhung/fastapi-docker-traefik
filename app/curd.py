from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import app.model, app.schemas
from sqlalchemy import desc
import string, random, datetime
from typing import Union, Annotated
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException,status, Depends
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
# from dotenv import load_dotenv
from database import SessionLocal
import os
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
'''
User management
'''
# User management
def get_user_by_id(db: Session, user_id: int):
    return db.query(model.User).filter(model.User.id == user_id).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.User).offset(skip).limit(limit).all()

def get_user_by_password(db: Session, password: str):
    return db.query(model.User).filter(model.User.password == password).first()

def create_user(db: Session, user: schemas.User):
    fake_hashed_password = get_password_hash(user.password)
    db_user = model.User(username=user.username, password=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
'''
Agent management
'''
# Agent management
def create_agents(db: Session, agents: schemas.agents):
    db_agent = model.agents(name=agents.name, token= create_token(db=db), zalo_name=agents.zalo_name, zalo_number_target=agents.zalo_number_target, webhook_id=agents.webhook_id, created_at=datetime.now(), ended_at=datetime.now())
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return db_agent

def get_agents_by_id(db: Session, agent_id: int):
    return db.query(model.agents).filter(model.agents.id == agent_id).first()

def get_agents_by_token(db: Session, token:str):
    return db.query(model.agents).filter(model.agents.token == token).first()

def get_limit_agents(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.agents).offset(skip).limit(limit).all()
'''
Create new token wihout exist database
'''
def check_exists_token(db: Session, token:str):
    token = db.query(model.agents).filter(model.agents.token == token).first()
    if token:
        return True
    else:
        return False
'''
webhooks management
'''
# Webhooks management
# Insert webhooks into database
def create_webhooks(db: Session, webhooks: schemas.webhooks):
    webhooks = model.webhooks(url_webhook=webhooks.url_webhook, webhook_name= webhooks.webhook_name, created_at= datetime.now(), ended_at= datetime.now() )
    db.add(webhooks)
    db.commit()
    db.refresh(webhooks)
    return webhooks
# get Webhooks by ID
def get_webhooks_by_id(db: Session, id:int):
    return db.query(model.webhooks).filter(model.webhooks.id == id).first()


'''
logger management
'''
def create_logger(db: Session, loggers: schemas.loggers):
    logger = model.logger( ip=loggers.ip, user_agents=loggers.user_agents, device=loggers.device, ip_info=loggers.ip_info, filename=loggers.filename, token=loggers.token, time_stamp=loggers.time_stamp, created_at=loggers.created_at)
    db.add(logger)
    db.commit()
    db.refresh(logger)
    return logger

def get_logger_by_token(db:Session, token:str, limit:int):
    try:
        return db.query(model.logger).filter(model.logger.token == token).order_by(desc(model.logger.time_stamp)).limit(limit).all()
    except SQLAlchemyError as e:
        return {"message": "An error occurred while retrieving the logs", "error": str(e)}
def get_logger_by_id(db:Session, id: int):
    try:
        return db.query(model.logger).filter(model.logger.id == id).limit(10).all()
    except SQLAlchemyError as e:
        return {"message": "An error occurred while retrieving the logs", "error": str(e)}
'''
    Logger Error Management
'''
def create_logger_error(db: Session, logger_error: schemas.logger_error):
    logger_error = model.logger_error( ip=logger_error.ip, user_agents=logger_error.user_agents, device=logger_error.device, ip_info=logger_error.ip_info, filename=logger_error.filename, token=logger_error.token, time_stamp=logger_error.time_stamp, created_at=datetime.now())
    db.add(logger_error)
    db.commit()
    db.refresh(logger_error)
    return logger_error
# get_logger_error
def get_logger_error_by_token(db:Session, token:str, limit:int):
    try:
        return db.query(model.logger_error).filter(model.logger_error.token == token).order_by(desc(model.logger_error.time_stamp)).limit(limit).all()
    except SQLAlchemyError as e:
        return {"message": "An error occurred while retrieving the logs", "error": str(e)}
# get_logger_error_by_id
def get_logger_error_by_id(db:Session, id: int):
    try:
        return db.query(model.logger_error).filter(model.logger_error.id == id).limit(10).all()
    except SQLAlchemyError as e:
        return {"message": "An error occurred while retrieving the logs", "error": str(e)}

'''
Uitls
'''
def create_token(db: Session):
    while True:
        random_token = generate_random_string(8)
        bool_check_token =check_exists_token(db, random_token)
        if not bool_check_token:
            break
    return random_token
def generate_random_string(length):
    # Define the characters to choose from
    characters = string.ascii_letters + string.digits
    # Generate a random string of the specified length
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
'''
User credentials management
'''
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

    
def authenticate_user(username: str ,password: str, db:Session ):
    user = db.query(model.User).filter(model.User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY  , algorithm=ALGORITHM)
    return encoded_jwt

