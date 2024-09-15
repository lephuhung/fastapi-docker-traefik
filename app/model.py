from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    # items = relationship("Item", back_populates="owner")

class token(Base):
    __tablename__ = 'token'

    id = Column(Integer, primary_key=True, index=True)
    token_type = Column(String)
    token = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

class phone (Base):
    __tablename__ = 'phone'
    
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String)
    phone_user = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    zns_message = relationship("zns_message", back_populates="phone")

class zns (Base):
    __tablename__ = 'zns'

    id = Column(Integer, primary_key=True, index=True)
    zns_id = Column(String)
    zns_name = Column(String)
    zns_value = Column(String)
    discord_url = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

class zns_message (Base):
    __tablename__ ='zns_message'

    id = Column(Integer, primary_key=True, index=True)
    phone_id = Column(Integer, ForeignKey('phone.id'))
    message_id = Column(String)
    zns_id = Column (String)
    message = Column(String)
    time_stamp = Column(String)
    time_send = Column (String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    phone = relationship("phone", back_populates="zns_message")


class agents(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    token = Column(String)
    zalo_name = Column(String)
    zalo_number_target = Column(String)
    created_at = Column(DateTime)
    ended_at = Column(DateTime)
    webhook_id = Column(Integer, ForeignKey("webhooks.id"))

    # owner = relationship("User", back_populates="items")


class webhooks(Base):
    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, index=True)
    url_webhook = Column(String)
    webhook_name = Column(String)
    created_at = Column(DateTime)
    ended_at = Column(DateTime)

class logger(Base):
    __tablename__ = "logger"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    user_agents = Column(String)
    device=Column(String)
    ip_info = Column(String)
    filename = Column(String)
    token = Column(String, ForeignKey("agents.token"))
    time_stamp = Column(DateTime)
    created_at = Column(DateTime)

class logger_error(Base):
    __tablename__="logger_error"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    user_agents = Column(String)
    device=Column(String)
    ip_info = Column(String)
    filename = Column(String, None)
    token = Column(String, None, ForeignKey("agents.token"))
    time_stamp = Column(DateTime)
    created_at = Column(DateTime)

class ip (Base):
    __tablename__='ip'
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

class uap_data (Base):
    __tablename__= 'uap_data'
    id = Column(Integer, primary_key=True, index= True)
    browser_name = Column(String)
    browser_version = Column(String)
    os_name = Column(String)
    os_version= Column(String)
    device_model = Column(String)
    device_type = Column(String)
    device_vendor = Column(String)
    user_agent = Column(String)
    token = Column(String)
    ip = Column(String)
    phone = Column(String)
    timestamp = Column(DateTime)

class og_data(Base):
    __tablename__='og_data'
    id = Column(Integer, primary_key= True, index = True)
    token= Column(String)
    og_title = Column(String)
    og_description = Column(String)
    og_image = Column(String)
    og_url = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
