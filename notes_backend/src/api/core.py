import os
import datetime
from typing import Optional, List

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

from sqlalchemy.orm import Session

from src.db.models import User, Note
from src.db.db import get_db

# === Security config from env ===
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "notsosecret")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# ==== Pydantic Schemas ====

# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    """Schema for user creation (signup) input."""
    email: EmailStr
    password: str = Field(..., min_length=6)

# PUBLIC_INTERFACE
class UserRead(BaseModel):
    """Schema for returning user info (without password)."""
    id: int
    email: EmailStr
    created_at: datetime.datetime

    class Config:
        orm_mode = True

# PUBLIC_INTERFACE
class Token(BaseModel):
    """Returned when authenticating successfully."""
    access_token: str
    token_type: str

# PUBLIC_INTERFACE
class NoteBase(BaseModel):
    """Base schema for notes."""
    title: str
    content: Optional[str] = ""

# PUBLIC_INTERFACE
class NoteCreate(NoteBase):
    """Input schema for creating a note."""

# PUBLIC_INTERFACE
class NoteUpdate(NoteBase):
    """Input schema for updating a note."""

# PUBLIC_INTERFACE
class NoteRead(NoteBase):
    """Returned data for a note."""
    id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime
    user_id: int

    class Config:
        orm_mode = True

# ==== Utility functions ====

# PUBLIC_INTERFACE
def get_password_hash(password: str) -> str:
    """Hash the plain password."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """Authenticate user by email and password."""
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Generate a secure JWT access token."""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# PUBLIC_INTERFACE
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """Get current user from JWT token, fails with 401 if invalid."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).get(user_id)
    if user is None:
        raise credentials_exception
    return user

# === CRUD for Users and Notes (used by API routes) ===

# PUBLIC_INTERFACE
def create_user(db: Session, user: UserCreate) -> User:
    """Create a new user, raises HTTPException if email taken."""
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    db_user = User(
        email=user.email,
        password_hash=get_password_hash(user.password),
        created_at=datetime.datetime.utcnow()
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# PUBLIC_INTERFACE
def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """Get a user by ID, or None if not found."""
    return db.query(User).get(user_id)

# PUBLIC_INTERFACE
def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get a user by email address."""
    return db.query(User).filter(User.email == email).first()

# PUBLIC_INTERFACE
def create_note(db: Session, user: User, note: NoteCreate) -> Note:
    """Create a note for the authenticated user."""
    db_note = Note(
        title=note.title,
        content=note.content,
        user_id=user.id
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

# PUBLIC_INTERFACE
def get_notes(db: Session, user: User, skip=0, limit=100, search: Optional[str]=None) -> List[Note]:
    """List notes owned by the user, optionally search by title/content."""
    query = db.query(Note).filter(Note.user_id == user.id)
    if search:
        pattern = f"%{search}%"
        query = query.filter((Note.title.ilike(pattern)) | (Note.content.ilike(pattern)))
    return query.offset(skip).limit(limit).all()

# PUBLIC_INTERFACE
def get_note(db: Session, user: User, note_id: int) -> Note:
    """Get a single note owned by user, raises 404 if not found or not theirs."""
    note = db.query(Note).filter(Note.id == note_id, Note.user_id == user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

# PUBLIC_INTERFACE
def update_note(db: Session, user: User, note_id: int, note_update: NoteUpdate) -> Note:
    """Update a note (must be owned by current user)."""
    note = get_note(db, user, note_id)
    note.title = note_update.title
    note.content = note_update.content
    note.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
def delete_note(db: Session, user: User, note_id: int):
    """Remove a note. Raises 404 if not found, 403 if not user's."""
    note = get_note(db, user, note_id)
    db.delete(note)
    db.commit()
