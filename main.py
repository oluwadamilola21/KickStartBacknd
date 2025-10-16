from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User
from schemas import UserCreate, LoginRequest
from schemas import ForgotPasswordRequest, ResetPasswordRequest
from email_utils import send_password_reset_email
from schemas import ContactRequest, ContactResponse
from models import ContactMessage
from auth import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM, EXPIRE_MINUTES
from email_utils import send_verification_email
from jose import jwt, JWTError
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from email_utils import send_admin_contact_notification
from database import get_db
from datetime import datetime, timedelta
import os
import re
import logging
from crud import get_user_by_email, get_user_by_username, create_user
from models import VideoProgress
from schemas import ProgressCreate, ProgressOut

# Initialize DB
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ "https://kick-start-digital-hub.netlify.app","http://localhost:5173","https://kickstartbacknd.onrender.com",],
    allow_credentials=True,
    allow_methods=["*"],  # allow all HTTP methods
    allow_headers=["*"],  # allow all headers
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_username(db, user.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered.")
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$', user.password):
        raise HTTPException(status_code=400, detail="Password cannot be less than 8 characters {contain an uppercase,lowercase,number and special character}")
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$', user.password):
        raise HTTPException(status_code=400, detail="Password cannot be less than 8 characters {contain an uppercase,lowercase,number and special character}")

    token_data = {
        "sub": user.email,
        "exp": datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    hashed_pw = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_pw, is_verified=False, verification_token=token)
    create_user(db, new_user)

    await send_verification_email(user.email, token)
    return {"message": "User created. Check your email to verify your account."}

@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        return RedirectResponse(url=f"{os.getenv('FRONTEND_URL')}/signin?verified=false")
    if user.is_verified:
        return RedirectResponse(url=f"{os.getenv('FRONTEND_URL')}/dashboard")

    user.is_verified = True
    user.verification_token = None
    db.commit()
    return RedirectResponse(url=f"{os.getenv('FRONTEND_URL')}/signin?verified=true")

@app.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = get_user_by_email(db, data.email)
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid Login details")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    token = create_access_token({"sub": user.username, "email": user.email})
    return {"access_token": token, "token_type": "bearer", "username": user.username}



@app.get("/delete-email")
def delete_email(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": f"User with email {email} deleted."}

@app.get("/delete-user")
def delete_user(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": f"User {username} deleted."}

@app.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    token_data = {
        "sub": user.email,
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    user.reset_token = token
    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=30)
    db.commit()

    try:
        await send_password_reset_email(user.email, token)  # no await!
    except Exception as e:
        logging.error(f"Error sending reset email: {e}")
        raise HTTPException(status_code=500, detail="Email sending failed")

    return {"message": "Password reset link sent to your email."}

@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    if data.new_password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&]).{8,}$', data.new_password):
        raise HTTPException(status_code=400, detail="Password must be strong")

    # Decode JWT token only
    try:
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.hashed_password = get_password_hash(data.new_password)
    db.commit()

    return {"message": "Password has been reset successfully."}

@app.post("/contact", response_model=ContactResponse, status_code=status.HTTP_201_CREATED)
def submit_contact_message(payload: ContactRequest, db: Session = Depends(get_db)):
    message = ContactMessage(
        name=payload.name,
        email=payload.email,
        subject=payload.subject,
        message=payload.message
    )
    db.add(message)
    db.commit()

    # Send email to admin
    try:
        send_admin_contact_notification(
            name=payload.name,
            email=payload.email,
            subject=payload.subject,
            message=payload.message
        )
    except Exception as e:
        logging.error(f"Failed to send contact email: {e}")

    return {"message": "Your message has been received. We'll get back to you shortly."}


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/save", response_model=ProgressOut)
def save_progress(data: ProgressCreate, db: Session = Depends(get_db), user: int = Depends(get_current_user)):
    existing = db.query(VideoProgress).filter_by(user_id=user.id, video_id=data.video_id).first()
    if existing:
        existing.progress = data.progress
        existing.completed = data.completed
    else:
        existing = VideoProgress(user_id=user.id, video_id=data.video_id, progress=data.progress, completed=data.completed )
        db.add(existing)
    db.commit()
    db.refresh(existing)
    return existing

@app.get("/get/{video_id}", response_model=ProgressOut)
def get_progress(video_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    existing = db.query(VideoProgress).filter_by(user_id=user.id, video_id=video_id).first()
    if not existing:
        return ProgressOut(video_id=video_id, progress=0.0)
    return existing

