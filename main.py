from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from fastapi.responses import JSONResponse
from fastapi_ratelimit import RateLimiter
from fastapi.middleware.cors import CORSMiddleware
from fastapi_ratelimit.backends import AIOBackend
from cloudinary.uploader import upload  # Імпортуйте функцію завантаження з Cloudinary

from app import crud, models, schemas
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = FastAPI()

# Увімкнення CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфігурації Cloudinary
cloudinary.config(
    cloud_name="your_cloud_name",
    api_key="your_api_key",
    api_secret="your_api_secret"
)

rate_limiter = RateLimiter(calls=5, period=1)
DATABASE_URL = "postgresql://postgres:admin1234@localhost/database"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
models.Base.metadata.create_all(bind=engine)

SECRET_KEY = "123456"
ALGORITHM = "HS256"

backend = AIOBackend()
limiter = RateLimiter(
    backend=backend,
    global_limits=("100 per minute",),
    individual_limits={},
)


def get_db():
    """
    Отримання сесії бази даних.

    :return: Об'єкт сесії бази даних
    """

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_jwt_token(data: dict, expires_delta: timedelta):
    """
    Створення JWT-токену.

    :param data: Дані для кодування у токені
    :param expires_delta: Тривалість дії токену
    :return: Створений JWT-токен
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_tokens(data: dict):
    access_token_expires = timedelta(minutes=15)
    refresh_token_expires = timedelta(days=7)

    access_token = create_jwt_token(data, access_token_expires)
    refresh_token = create_refresh_token(data, refresh_token_expires)
    return access_token, refresh_token

def decode_jwt_token(token: str):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_jwt_token(token)
        return payload
    except Exception as e:
        raise credentials_exception from e

@app.post("/register", response_model=dict)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=409, detail="Username already registered")

    # Hash the password before storing it in the database
    user.password = crud.hash_password(user.password)

    # Create the user and generate tokens
    db_user = crud.create_user(db=db, user=user)
    access_token, refresh_token = create_tokens(data={"sub": db_user.username})

    verification_token = crud.generate_verification_token()  # Якщо це функція в вашому модулі crud
    crud.update_verification_token(db, db_user.id, verification_token)  # Якщо це функція в вашому модулі crud

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/token", response_model=dict)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, form_data.username)
    if db_user and crud.verify_password(form_data.password, db_user.password):
        access_token, refresh_token = create_tokens(data={"sub": db_user.username})
        return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}
    raise HTTPException(status_code=401, detail="Incorrect username or password")

@app.get("/protected", response_model=dict)
def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": "This is a protected route", "current_user": current_user}

@app.get("/verify-email/{verification_token}", response_model=dict)
def verify_email(verification_token: str, db: Session = Depends(get_db)):
    # Пошук користувача за токеном верифікації
    db_user = crud.get_user_by_verification_token(db, verification_token)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")

    # Оновлення статусу верифікації та очищення токену
    db_user.email_verified = True
    db_user.verification_token = ""
    db.commit()

    return {"message": "Email verification successful"}

@app.post("/contacts/", response_model=schemas.ContactRead, dependencies=[Depends(limiter)])
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db),
                   current_user: dict = Depends(get_current_user)):
    try:
        if contact.owner != current_user["sub"]:
            raise HTTPException(status_code=403, detail="You don't have permission to create this contact")

        return crud.create_contact(db=db, contact=contact)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/upcoming_birthdays", response_model=dict, dependencies=[Depends(get_current_user)])
async def get_upcoming_birthdays_route(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    upcoming_birthdays = crud.get_upcoming_birthdays(db, current_user["sub"])
    return JSONResponse(content={"upcoming_birthdays": upcoming_birthdays})

@app.get("/contacts/", response_model=list[schemas.ContactRead])
def read_contacts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    try:
        return crud.get_contacts(db=db, skip=skip, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/contacts/{contact_id}", response_model=schemas.ContactRead)
def read_contact(contact_id: int, db: Session = Depends(get_db)):
    try:
        return crud.get_contact_by_id(db=db, contact_id=contact_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/contacts/{contact_id}", response_model=schemas.ContactRead)
def update_contact(contact_id: int, contact_update: schemas.ContactUpdate, db: Session = Depends(get_db)):
    try:
        return crud.update_contact(db=db, contact_id=contact_id, contact_update=contact_update)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/contacts/{contact_id}", response_model=schemas.ContactRead)
def delete_contact(contact_id: int, db: Session = Depends(get_db)):
    try:
        return crud.delete_contact(db=db, contact_id=contact_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/contacts/search/", response_model=list[schemas.ContactRead])
def search_contacts(query: str, db: Session = Depends(get_db)):
    try:
        return crud.search_contacts(db=db, query=query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update-avatar", response_model=dict)
async def update_avatar(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
        Оновлення аватара користувача за допомогою завантаження на Cloudinary.

        :param file: Завантажений файл аватара
        :param db: Об'єкт сесії бази даних
        :param current_user: Дані поточного користувача
        :return: Інформація про успішне оновлення аватара
        """

    try:
        # Завантажте файл на Cloudinary
        cloudinary_response = upload(file.file, folder="avatars")

        # Оновіть аватар користувача в базі даних
        avatar_url = cloudinary_response['secure_url']
        crud.update_user_avatar(db=db, user_id=current_user["sub"], avatar_url=avatar_url)

        return {"message": "Avatar updated successfully", "avatar_url": avatar_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))