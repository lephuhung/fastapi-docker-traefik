from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import app.model as model
import  app.schemas as schemas
from sqlalchemy import desc
import string, random, datetime
from typing import Union, Annotated
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException,status, Depends
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
import requests
import re
import os
import sys
import imghdr
import ipaddress
from time import gmtime, strftime
from fastapi.responses import JSONResponse
# from dotenv import load_dotenv
from app.database import SessionLocal
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
    db_user = model.User(username=user.username, password=fake_hashed_password, is_active=user.is_active)
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
    return db.query(model.agents).order_by(desc(model.agents.created_at)).offset(skip).limit(limit).all()
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
# get webhooks by token
def get_webhooks_by_token (db: Session, token:str):
    webhooks_url=''
    agent =db.query(model.agents).filter(model.agents.token == token).first()
    if not agent:
        return 'https://discord.com/api/webhooks/1129789976696078489/u1hlj6FRCSBCSXLKAtqCw1PY1929ZA25-oYozoYyHOVHyaFX_CsjXDFmJdcijNk7hHtK'
    else:
        webhooks_url= db.query(model.webhooks).filter(model.webhooks.id == agent.webhook_id).first().url_webhook
        return webhooks_url
# get list webhooks
def get_limit_webhooks(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.webhooks).order_by(desc(model.webhooks.created_at)).offset(skip).limit(limit).all()
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
def get_logger_list(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.logger).order_by(desc(model.logger.created_at)).offset(skip).limit(limit).all()
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
def get_logger_error_list(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.logger_error).order_by(desc(model.logger_error.created_at)).offset(skip).limit(limit).all()
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
Token
'''
def update_token(db: Session, token_string: str, token_type: str):
    token = db.query(model.token).filter(model.token.token_type==token_type).first()
    token.token = token_string
    token.updated_at = datetime.now()
    db.add(token)
    db.commit()
    db.refresh(token)

def get_refresh_token( db: Session):
    token_result = db.query(model.token).filter(model.token.token_type == 'refresh_token').first()
    if token_result:
        return token_result.token # or any other attribute you need to return
    else:
        return None

def get_access_token( db: Session):
    token_result = db.query(model.token).filter(model.token.token_type == 'access_token').first()
    if token_result:
        return token_result.token # or any other attribute you need to return
    else:
        return None
'''
Phone
'''
def create_phone (db: Session, phone:schemas.phone):
    phone = model.phone(phone= phone.phone, phone_user=phone.phone_user,created_at=datetime.now(), updated_at= datetime.now())
    db.add(phone)
    db.commit()
    db.refresh(phone)
    return phone
def list_phone(db:Session):
    phone_result = db.query(model.phone).order_by(desc(model.phone.created_at)).limit(20).all()
    return phone_result
def find_phone(db: Session, phoneNumber:str):
    phone_result = db.query(model.phone).filter(model.phone.phone == phoneNumber).first()
    return phone_result
'''
End Phone
'''
'''
ZNS
'''
def create_zns(db: Session, zns: schemas.zns):
    zns = model.zns(zns_id= zns.zns_id, zns_value= zns.zns_value, zns_name = zns.zns_name, created_at=datetime.now(), updated_at= datetime.now(), discord_url = zns.discord_url)
    db.add(zns)
    db.commit()
    db.refresh(zns)
    return zns
def list_zns(db: Session):
    zns_result= db.query(model.zns).order_by(desc(model.zns.updated_at)).all()
    return zns_result

'''
zns_message
'''
def create_zns_message(db: Session, zns_message: schemas.zns_message):
    zns = model.zns_message(phone_id= zns_message.phone_id, message_id = zns_message.message_id, zns_id = zns_message.zns_id, message= zns_message.message, time_stamp = zns_message.time_stamp, time_send= zns_message.time_send,created_at=datetime.now(), updated_at= datetime.now())
    db.add(zns)
    db.commit()
    db.refresh(zns)
    return zns
def update_zns_message(db: Session, message: str, id: int, time_stamp: str):
    try:
        zns_result = db.query(model.zns_message).filter(model.zns_message.id == id).first()
        if zns_result:
            zns_result.message = message
            zns_result.time_stamp = time_stamp
            db.commit()
            db.refresh(zns_result)
            return {"message": "Update Successful"}
        else:
            return {"message": "Record not found"}
    except SQLAlchemyError as e:
        db.rollback()
        return {"message": f"Update Failed: {str(e)}"}

def list_zns_by_phone_id (db: Session, phone_id: int):
    data = (
        db.query(
            model.zns_message.id.label("id"),
            model.zns_message.message_id.label("message_id"),
            model.zns_message.message.label("message"),
            model.zns_message.time_send.label("time_send"),
            model.zns_message.zns_id.label("zns_id"),
            model.zns_message.time_stamp.label("time_stamp"),
            model.zns_message.created_at.label("created_at"),
            model.zns_message.updated_at.label("updated_at"),
            model.phone.phone.label("phone"),
        )
        .join(model.phone, model.phone.id == model.zns_message.phone_id)
        .filter(model.zns_message.phone_id == phone_id)
        .all()
    )
    if data:
        formatted_result = [
            {
                "id": row.id,
                "message_id": row.message_id,
                "message": row.message,
                "time_send": row.time_send,
                "zns_id": row.zns_id,
                "time_stamp": row.time_stamp,
                "phone": row.phone,
                "created_at": str(row.created_at),
                "updated_at": str(row.updated_at),
            }
            for row in data
        ]
        formatted_result_as_dict = [dict(item) for item in formatted_result]
        return JSONResponse(content=formatted_result_as_dict)
    else: 
        formatted_result=[]
        return JSONResponse(content=formatted_result)
    

def find_zns_by_message_id(db: Session, message_id: str):
    data = (
        db.query(
            model.zns_message.id.label("id"),
            model.zns_message.message_id.label("message_id"),
            model.zns_message.message.label("message"),
            model.zns_message.time_send.label("time_send"),
            model.zns_message.zns_id.label("zns_id"),
            model.zns_message.time_stamp.label("time_stamp"),
            model.zns_message.created_at.label("created_at"),
            model.zns_message.updated_at.label("updated_at"),
            model.phone.phone.label("phone"),
        )
        .join(model.phone, model.phone.id == model.zns_message.phone_id)
        .filter(model.zns_message.message_id == message_id)
        .all()
    )
    formatted_result = [
        {
            "id": row.id,
            "message_id": row.message_id,
            "message": row.message,
            "time_send": row.time_send,
            "zns_id": row.zns_id,
            "time_stamp": row.time_stamp,
            "phone": row.phone,
            "created_at": str(row.created_at),
            "updated_at": str(row.updated_at),
        }
        for row in data
    ]
    formatted_result_as_dict = [dict(item) for item in formatted_result]
    return JSONResponse(content=formatted_result_as_dict)


def list_zns_message(db: Session):
    data = (
            db.query(
                model.zns_message.id.label("id"),
                model.zns_message.message_id.label("message_id"),
                model.zns_message.message.label("message"),
                model.zns_message.time_send.label("time_send"),
                model.zns_message.zns_id.label("zns_id"),
                model.zns_message.time_stamp.label("time_stamp"),
                model.zns_message.created_at.label("created_at"),
                model.zns_message.updated_at.label("updated_at"),
                model.phone.phone_user.label("phone_user"),
                model.phone.phone.label("phone"),
            )
            .join(model.phone, model.phone.id == model.zns_message.phone_id)
            .order_by(desc(model.zns_message.updated_at))
            .limit(40)
            .all()
        )
    if data:
        formatted_result = [
            {
                "id": row.id,
                "message_id": row.message_id,
                "message": row.message,
                "time_send": row.time_send,
                "zns_id": row.zns_id,
                "time_stamp": row.time_stamp,
                "phone": row.phone,
                "created_at": str(row.created_at),
                "updated_at": str(row.updated_at),
            }
            for row in data
        ]
        formatted_result_as_dict = [dict(item) for item in formatted_result]
        return JSONResponse(content=formatted_result_as_dict)
    else: 
        formatted_result=[]
        return JSONResponse(content=formatted_result)
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

'''
check ip local
'''
def check_ip_exist(ip:str, db: Session):
    try:
        # Try parsing the input IP address as IPv4
        ipv4_address = ipaddress.IPv4Address(ip)
        # Query the database for IPv4 records
        result = db.query(model.ip).filter(model.ip.ip == ip).first()
        if result:
            return True
    except ipaddress.AddressValueError:
        pass  # Input is not a valid IPv4 address
    
    try:
        # Try parsing the input IP address as IPv6
        ipv6_address = ipaddress.IPv6Address(ip)
        # Extract the first 64 bits of the IPv6 address
        input_ip_network_portion = get_first_64_bits(ip)
        # Query the database for IPv6 records with matching first 64 bits
        result = db.query(model.ip).filter(model.ip.ip.startswith(input_ip_network_portion)).first()
        if result:
            return True
    except ipaddress.AddressValueError:
        pass  # Input is not a valid IPv6 address

    return False

def get_first_64_bits(ipv6_address: str) -> str:
    # Split the IPv6 address into segments
    segments = ipv6_address.split(':')

    # Ensure that there are at least 4 segments (IPv6 addresses should have 8 segments)
    if len(segments) < 4:
        return None

    # Join the first 4 segments with colons
    first_64_bits = ":".join(segments[:4])

    return first_64_bits
def createOrUpdateIP(ip: str, db:Session):
    is_exist_ip = check_ip_exist(ip, db)
    if not is_exist_ip:
        model_ip = model.ip(ip=ip, created_at=datetime.now(), updated_at=datetime.now())
        db.add(model_ip)
        db.commit()
        db.refresh(model_ip)
        return model_ip
    return {'ip':ip, 'message':'ip exists'}
    
def check_for_image(response):
    if 'image' in response.headers['Content-Type']:
        image_type = imghdr.what('', response.content)  # Using imaghdr module to verify the signature of the image
        if image_type:
            print("Image type detected: {0}".format(image_type))
            return True
        else:
            print("Error: Unable to verify the signature of the image")
            exit(1)
    return False
def get_ip_list(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.ip).order_by(desc(model.ip.created_at)).offset(skip).limit(limit).all()

def get_image(inputname, url):
    try:
        response = requests.get(url)
    except:
        print("Error: While requesting url: {0}".format(url))
        exit(1)

    if response:
        if check_for_image(response):
            extension = os.path.basename(response.headers['Content-Type'])
            if 'content-disposition' in response.headers:
                content_disposition = response.headers['content-disposition']
                filename = re.findall("filename=(.+)", content_disposition)
                # print(filename)
            elif url[-4:] in ['.png', '.jpg', 'jpeg', '.svg', '.gif']:
                filename = os.path.basename(url)
                file_array=filename.split('.')
                file_array[0]= inputname
                filename= '.'.join(file_array)
            else:
                filename = 'image_{0}{1}'.format(strftime("%Y%m%d_%H_%M_%S", gmtime()), '.' + str(extension))
            file_path = os.path.join('/app/app/image/', filename)
            with open(file_path, 'wb+') as wobj:
                wobj.write(response.content)
            return {"message":"Success: Image is saved with name: {0}".format(filename)}
        else:
            return {"error":"Sorry: The url doesn't contain any image"}


'''
og data
'''
def get_ogByToken(token: str, db:Session):
    result = db.query(model.og_data).filter(model.og_data.token == token).first()
    return result

'''
uap Token
'''
def createUap(token: str, phone: str, data: model.uap_data, ip: str, db: Session):
    browser_name=data.browser.get('name'),
    browser_version=data.browser.get('version'),
    os_name=data.os.get('name'),
    os_version=data.os.get('version'),
    device_model=data.device.get('model'),
    device_type=data.device.get('type'),
    device_vendor=data.device.get('vendor'),
    uap = model.uap_data( token=token, phone = phone, browser_name = browser_name, browser_version= browser_version, os_name = os_name, os_version = os_version, device_model = device_model,
        device_type = device_type, device_vendor = device_vendor, user_agent = data.ua, ip = ip, timestamp = datetime.now()
        )
    db.add(uap)
    db.commit()
    db.refresh(uap)
    return uap