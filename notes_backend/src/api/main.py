from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Optional

from dotenv import load_dotenv

from src.api.core import (
    UserCreate, UserRead, Token,
    NoteCreate, NoteRead, NoteUpdate,
    get_db, get_current_user,
    create_user, authenticate_user, create_access_token,
    create_note, get_notes, get_note, update_note, delete_note
)
from src.db.models import User

# Load .env for DB/JWT settings
load_dotenv()

openapi_tags = [
    {"name": "auth", "description": "Authentication and login"},
    {"name": "users", "description": "User management"},
    {"name": "notes", "description": "Create, update, view, and delete notes"}
]

app = FastAPI(
    title="Notes Backend API",
    description="FastAPI backend for notes management (with Auth, CRUD, user).",
    version="1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["health"])
def health_check():
    """Health check root."""
    return {"message": "Healthy"}

# --- Authentication Endpoints ---

# PUBLIC_INTERFACE
@app.post("/auth/signup", response_model=UserRead, tags=["auth"], summary="Register a new user")
def signup(user: UserCreate, db=Depends(get_db)):
    """Register a new user. Email must be unique."""
    created = create_user(db, user)
    return created

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["auth"], summary="Obtain JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    """
    Authenticate and get JWT token using OAuth2 form (username is email).
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(data={"sub": user.id})
    return {"access_token": token, "token_type": "bearer"}

# --- User Endpoints ---

# PUBLIC_INTERFACE
@app.get("/users/me", response_model=UserRead, tags=["users"], summary="Get current user info")
def read_current_user(current_user: User = Depends(get_current_user)):
    """Get info on current authenticated user."""
    return current_user

# --- Notes Endpoints ---

# PUBLIC_INTERFACE
@app.post("/notes/", response_model=NoteRead, tags=["notes"], summary="Create a new note")
def create_user_note(note: NoteCreate, db=Depends(get_db), current_user: User=Depends(get_current_user)):
    """Create note belonging to authenticated user."""
    return create_note(db, current_user, note)

# PUBLIC_INTERFACE
@app.get("/notes/", response_model=List[NoteRead], tags=["notes"], summary="List my notes")
def list_notes(
    db=Depends(get_db),
    current_user: User=Depends(get_current_user),
    skip: int = 0,
    limit: int = Query(100, le=100),
    search: Optional[str] = None
):
    """List notes. Use ?search=foo for term search in title/content."""
    return get_notes(db, current_user, skip, limit, search)

# PUBLIC_INTERFACE
@app.get("/notes/{note_id}", response_model=NoteRead, tags=["notes"], summary="Get specific note")
def get_user_note(note_id: int, db=Depends(get_db), current_user: User=Depends(get_current_user)):
    """Get a single note by ID (must be owned by the current user)."""
    return get_note(db, current_user, note_id)

# PUBLIC_INTERFACE
@app.put("/notes/{note_id}", response_model=NoteRead, tags=["notes"], summary="Update a note")
def update_user_note(note_id: int, note: NoteUpdate, db=Depends(get_db), current_user: User=Depends(get_current_user)):
    """Edit an existing note (must belong to user)."""
    return update_note(db, current_user, note_id, note)

# PUBLIC_INTERFACE
@app.delete("/notes/{note_id}", tags=["notes"], summary="Delete a note", status_code=204)
def delete_user_note(note_id: int, db=Depends(get_db), current_user: User=Depends(get_current_user)):
    """Delete one of your notes."""
    delete_note(db, current_user, note_id)
    return None

# --- OpenAPI doc endpoint for websocket info, etc. (if implemented in future) ---
@app.get("/docs/help", tags=["health"])
def docs_info():
    """
    Usage and endpoints reference. See /docs and /openapi.json for details.
    """
    return {
        "message": "Refer to /docs and /openapi.json for full REST API description."
    }

