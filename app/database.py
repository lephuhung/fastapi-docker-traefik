from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://fastapi_traefik_prod:fastapi_traefik_prod@clmm24h.io:5432/fastapi_traefik_prod"
SQLALCHEMY_DATABASE_URL = "postgresql://fastapi_traefik_prod:fastapi_traefik_prod@db:5432/fastapi_traefik_prod"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
