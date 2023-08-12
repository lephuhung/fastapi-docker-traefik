from typing import Union
from datetime import datetime
from pydantic import BaseModel


class User(BaseModel):
    username: str
    password: str
    is_active: Union[bool, None] = None

    class Config:
        from_attributes = True

class CurrentUser(BaseModel):
    username: str
    is_active: Union[bool, None] = None
    class Config:
        from_attributes = True

class UserInDB(User):
    password: str

    class Config:
        from_attributes = True


class agents(BaseModel):
    name: str
    zalo_name: str
    zalo_number_target: str
    webhook_id: int
    # created_at: datetime
    # ended_at: datetime

    class Config:
        from_attributes = True


class webhooks(BaseModel):
    url_webhook: str
    webhook_name: str
    # created_at: datetime
    # ended_at: datetime

    class Config:
        from_attributes = True


class loggers(BaseModel):
    ip: str
    user_agents: str
    device: str
    ip_info: str
    filename: str
    token: str
    time_stamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class logger_error(BaseModel):
    ip: str
    user_agents: str
    device: str
    ip_info: str
    filename: Union[str, None] = None
    token: Union[str, None] = None
    time_stamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None
