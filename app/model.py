from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    # items = relationship("Item", back_populates="owner")


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