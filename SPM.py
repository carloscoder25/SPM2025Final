# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import uvicorn

# Configuración básica
SECRET_KEY = "tu_clave_secreta_super_segura"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
        "role": "athlete"
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    role: str

class UserInDB(User):
    hashed_password: str

class AthleteData(BaseModel):
    heart_rate: int
    spo2: int
    timestamp: datetime
    steps: Optional[int] = None
    calories: Optional[float] = None

class TrainingSession(BaseModel):
    id: int
    athlete_id: int
    start_time: datetime
    end_time: datetime
    avg_heart_rate: int
    max_heart_rate: int
    min_spo2: int

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="SPM API",
    description="API para el sistema Sport Performance Metrics",
    version="1.0.0",
    openapi_tags=[{
        "name": "auth",
        "description": "Operaciones de autenticación"
    }, {
        "name": "athletes",
        "description": "Operaciones con datos de atletas"
    }, {
        "name": "coaches",
        "description": "Operaciones para entrenadores"
    }]
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token, tags=["auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User, tags=["auth"])
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Endpoints para atletas
@app.post("/athlete/data", tags=["athletes"])
async def submit_athlete_data(
    data: AthleteData,
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role != "athlete":
        raise HTTPException(status_code=403, detail="Only athletes can submit data")
    
    # Aquí iría la lógica para guardar los datos en la base de datos real
    return {
        "message": "Data received successfully",
        "data": data,
        "user": current_user.username
    }

@app.get("/athlete/history", tags=["athletes"])
async def get_athlete_history(
    current_user: User = Depends(get_current_active_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    # Datos de ejemplo para la respuesta
    example_data = [
        {
            "heart_rate": 72,
            "spo2": 98,
            "timestamp": "2023-05-01T08:00:00",
            "steps": 0
        },
        {
            "heart_rate": 120,
            "spo2": 97,
            "timestamp": "2023-05-01T09:30:00",
            "steps": 1500
        }
    ]
    
    return {
        "user": current_user.username,
        "data": example_data
    }

@app.get("/athlete/sessions", tags=["athletes"])
async def get_training_sessions(
    current_user: User = Depends(get_current_active_user)
):
    # Datos de ejemplo para sesiones de entrenamiento
    example_sessions = [
        {
            "id": 1,
            "start_time": "2023-05-01T08:00:00",
            "end_time": "2023-05-01T09:00:00",
            "avg_heart_rate": 120,
            "max_heart_rate": 145,
            "min_spo2": 96
        },
        {
            "id": 2,
            "start_time": "2023-05-02T17:00:00",
            "end_time": "2023-05-02T18:30:00",
            "avg_heart_rate": 135,
            "max_heart_rate": 155,
            "min_spo2": 94
        }
    ]
    
    return {
        "user": current_user.username,
        "sessions": example_sessions
    }

# Endpoints para entrenadores
@app.get("/coach/athletes", tags=["coaches"])
async def get_coach_athletes(
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role != "coach":
        raise HTTPException(status_code=403, detail="Only coaches can access this endpoint")
    
    # Datos de ejemplo para atletas
    example_athletes = [
        {
            "id": 1,
            "name": "Athlete One",
            "last_session": "2023-05-01",
            "avg_heart_rate": 125,
            "avg_spo2": 97
        },
        {
            "id": 2,
            "name": "Athlete Two",
            "last_session": "2023-05-02",
            "avg_heart_rate": 118,
            "avg_spo2": 98
        }
    ]
    
    return {
        "coach": current_user.username,
        "athletes": example_athletes
    }

@app.get("/coach/athlete/{athlete_id}", tags=["coaches"])
async def get_athlete_details(
    athlete_id: int,
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role != "coach":
        raise HTTPException(status_code=403, detail="Only coaches can access this endpoint")
    
    # Datos de ejemplo para un atleta específico
    example_athlete = {
        "id": athlete_id,
        "name": f"Athlete {athlete_id}",
        "last_week_data": {
            "avg_heart_rate": 120,
            "max_heart_rate": 150,
            "min_spo2": 95,
            "total_steps": 45000,
            "calories_burned": 3500
        },
        "last_sessions": [
            {
                "date": "2023-05-01",
                "duration": "1:15:00",
                "intensity": "high"
            },
            {
                "date": "2023-04-28",
                "duration": "0:45:00",
                "intensity": "medium"
            }
        ]
    }
    
    return example_athlete

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)