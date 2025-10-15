from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import List

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_verified: bool

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str
    
class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str

class ContactResponse(BaseModel):
    message: str

class ProgressBase(BaseModel):
    video_id: str
    progress: float

class ProgressCreate(BaseModel):
    video_id: str
    progress: float
    completed: bool = False   # optional, default False

class ProgressOut(ProgressBase):
    id: int | None = None

    class Config:
        from_attributes = True