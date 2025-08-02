"""Library Management API - Phase 2 Enhanced"""
import hashlib
import os
import shutil
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List
import uvicorn
import jwt
import bcrypt
from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# JWT Configuration
# In production, use environment variable
SECRET_KEY = "library-management-secret-key-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database Configuration
SQLALCHEMY_DATABASE_URL = "sqlite:///./library_management.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={
                       "check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# File Upload Configuration
UPLOAD_DIR = "uploads/books"
ALLOWED_EXTENSIONS = {".pdf", ".epub", ".txt", ".doc", ".docx"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Create upload directory
Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Library Management API - Enhanced",
    description="API for managing library books with JWT auth, database, and file uploads.",
    version="2.0.0",
)

# Mount static files for book downloads
app.mount("/static", StaticFiles(directory="uploads"), name="static")

# Security
security = HTTPBearer()


class UserRole(str, Enum):
    """Enum for user roles."""
    ADMIN = "admin"
    STUDENT = "student"


class BookStatus(str, Enum):
    """Enum for book status."""
    AVAILABLE = "available"
    ISSUED = "issued"


class IssueStatus(str, Enum):
    """Enum for issue status."""
    ACTIVE = "active"
    RETURNED = "returned"
    OVERDUE = "overdue"

# Database Models


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    max_books_allowed = Column(Integer, default=5)  # Issue limit per user
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    issues = relationship("BookIssue", back_populates="user")
    created_books = relationship("Book", back_populates="creator")


class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False, index=True)
    author = Column(String, nullable=False, index=True)
    description = Column(Text)
    isbn = Column(String, unique=True, index=True)
    category = Column(String, nullable=False, index=True)
    total_copies = Column(Integer, default=1)
    available_copies = Column(Integer, default=1)
    file_path = Column(String)  # Path to uploaded book file
    file_name = Column(String)  # Original filename
    file_size = Column(Integer)  # File size in bytes
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"))

    # Relationships
    creator = relationship("User", back_populates="created_books")
    issues = relationship("BookIssue", back_populates="book")


class BookIssue(Base):
    __tablename__ = "book_issues"

    id = Column(Integer, primary_key=True, index=True)
    book_id = Column(Integer, ForeignKey("books.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)
    due_date = Column(DateTime, nullable=False)
    return_date = Column(DateTime)
    status = Column(String, default=IssueStatus.ACTIVE)
    fine_amount = Column(Float, default=0.0)

    # Relationships
    book = relationship("Book", back_populates="issues")
    user = relationship("User", back_populates="issues")


# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Models (keeping your original structure)


class UserResgistration(BaseModel):  # Keeping your typo for compatibility
    """Model for user registration."""
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.STUDENT


class UserLogin(BaseModel):
    """Model for user login."""
    username: str
    password: str


class Token(BaseModel):
    """Model for JWT token response."""
    access_token: str
    token_type: str
    expires_in: int
    user: dict


class UserResponse(BaseModel):
    """Model for user response."""
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    max_books_allowed: int
    created_at: datetime

    class Config:
        from_attributes = True


class BookCreate(BaseModel):
    """Model for creating a book."""
    title: str
    author: str
    description: str
    isbn: Optional[str] = None
    category: str
    total_copies: int = 1


class BookResponse(BaseModel):
    """Model for the response of a book."""
    id: int
    title: str
    author: str
    description: str
    isbn: Optional[str]
    category: str
    total_copies: int
    available_copies: int
    file_name: Optional[str]
    file_size: Optional[int]
    created_at: datetime
    created_by: int

    class Config:
        from_attributes = True


class BookUpdate(BaseModel):
    """Model for updating a book."""
    title: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    isbn: Optional[str] = None
    category: Optional[str] = None
    total_copies: Optional[int] = None


class BookIssueRequest(BaseModel):
    """Model for issuing a book request."""
    book_id: int


class IssueResponse(BaseModel):
    """Model for the response of issuing a book."""
    id: int
    book_id: int
    user_id: int
    issued_at: datetime
    due_date: datetime
    return_date: Optional[datetime]
    status: str
    fine_amount: float
    book_title: Optional[str] = None
    user_username: Optional[str] = None

    class Config:
        from_attributes = True

# Database Dependency


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Enhanced Password Functions


def hash_password(password: str) -> str:
    """Hash password using bcrypt (more secure than SHA-256)."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# JWT Functions


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Please login again.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(credentials.credentials,
                             SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception

    return user


def required_admin(current_user: User = Depends(get_current_user)):
    """Dependency to ensure the user is an admin."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# File Upload Functions


def save_uploaded_file(file: UploadFile) -> tuple[str, int]:
    """Save uploaded file and return (file_path, file_size)."""
    # Validate file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_ext} not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    # Save file
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Get file size
        file_size = os.path.getsize(file_path)

        # Check file size
        if file_size > MAX_FILE_SIZE:
            os.remove(file_path)  # Clean up
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File too large. Maximum size: {MAX_FILE_SIZE/1024/1024:.1f}MB"
            )

        return file_path, file_size

    except Exception as e:
        # Clean up on error
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File upload failed"
        )

# Authentication Routes (Enhanced from your original)


@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserResgistration, db: Session = Depends(get_db)) -> UserResponse:
    """Register a new user."""
    # Check if username exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )

    # Check if email exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user with bcrypt hashing
    hashed_password = hash_password(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        role=user_data.role
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/auth/login", response_model=Token)
def login_user(credentials: UserLogin, db: Session = Depends(get_db)) -> Token:
    """Login the current user and return JWT token."""
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )

    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    )


@app.post("/auth/logout")
def logout_user() -> dict:
    """Logout the current user (JWT tokens are stateless, so this is informational)."""
    return {
        "message": "Logout successful. Please discard your access token.",
        "note": "JWT tokens are stateless. Token will expire automatically."
    }


@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Get the current user's information."""
    return current_user

# Book Management Routes (Enhanced with File Upload)


@app.post("/books/", response_model=BookResponse, status_code=status.HTTP_201_CREATED)
def create_book(
    title: str = Form(...),
    author: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    isbn: Optional[str] = Form(None),
    total_copies: int = Form(1),
    file: Optional[UploadFile] = File(None),
    admin_user: User = Depends(required_admin),
    db: Session = Depends(get_db)
) -> BookResponse:
    """Create a new book with optional file upload (Admin only)."""

    # Handle file upload
    file_path = None
    file_size = None
    file_name = None

    if file:
        file_path, file_size = save_uploaded_file(file)
        file_name = file.filename

    # Create book record
    db_book = Book(
        title=title,
        author=author,
        description=description,
        isbn=isbn,
        category=category,
        total_copies=total_copies,
        available_copies=total_copies,
        file_path=file_path,
        file_name=file_name,
        file_size=file_size,
        created_by=admin_user.id
    )

    db.add(db_book)
    db.commit()
    db.refresh(db_book)

    return db_book


@app.get("/books/", response_model=List[BookResponse])
def get_all_books(
    skip: int = 0,
    limit: int = 10,
    category: Optional[str] = None,
    search: Optional[str] = None,
    available_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> List[BookResponse]:
    """Get a list of all books with optional filters."""

    query = db.query(Book)

    # Apply filters
    if category:
        query = query.filter(Book.category.ilike(f"%{category}%"))

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Book.title.ilike(search_term)) |
            (Book.author.ilike(search_term)) |
            (Book.description.ilike(search_term))
        )

    if available_only:
        query = query.filter(Book.available_copies > 0)

    # Apply pagination
    books = query.offset(skip).limit(limit).all()
    return books


@app.get("/books/{book_id}", response_model=BookResponse)
def get_book(book_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> BookResponse:
    """Get a specific book by ID"""
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Book with ID {book_id} not found"
        )
    return book


@app.get("/books/{book_id}/download")
def download_book_file(book_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Download book file."""
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")

    if not book.file_path or not os.path.exists(book.file_path):
        raise HTTPException(status_code=404, detail="Book file not found")

    return FileResponse(
        book.file_path,
        filename=book.file_name,
        media_type='application/octet-stream'
    )


@app.put("/books/{book_id}", response_model=BookResponse)
def update_book(book_id: int, book_update: BookUpdate, admin_user: User = Depends(required_admin), db: Session = Depends(get_db)) -> BookResponse:
    """Update a book (Admin only)."""
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")

    # Update fields
    update_data = book_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(book, field, value)

    # Update available copies if total copies changed
    if "total_copies" in update_data:
        issued_count = db.query(BookIssue).filter(
            BookIssue.book_id == book_id,
            BookIssue.status == IssueStatus.ACTIVE
        ).count()
        book.available_copies = max(0, book.total_copies - issued_count)

    db.commit()
    db.refresh(book)
    return book


@app.delete("/books/{book_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_book(book_id: int, admin_user: User = Depends(required_admin), db: Session = Depends(get_db)):
    """Delete a book by ID."""
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Book with ID {book_id} not found"
        )

    # Check if book has active issues
    active_issues = db.query(BookIssue).filter(
        BookIssue.book_id == book_id,
        BookIssue.status == IssueStatus.ACTIVE
    ).count()

    if active_issues > 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete book with active issues"
        )

    # Delete associated file
    if book.file_path and os.path.exists(book.file_path):
        os.remove(book.file_path)

    db.delete(book)
    db.commit()

# Book Issue Routes (Enhanced with limits and fines)


@app.post("/books/issue", response_model=IssueResponse, status_code=status.HTTP_201_CREATED)
def issue_book(issue_request: BookIssueRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> IssueResponse:
    """Issue a book to current user with enhanced validation."""

    # Check book exists and is available
    book = db.query(Book).filter(Book.id == issue_request.book_id).first()
    if not book:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Book not found"
        )

    if book.available_copies <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Book is not available for issue"
        )

    # Check if user already has this book
    existing_issue = db.query(BookIssue).filter(
        BookIssue.book_id == issue_request.book_id,
        BookIssue.user_id == current_user.id,
        BookIssue.status == IssueStatus.ACTIVE
    ).first()

    if existing_issue:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already issued this book"
        )

    # Check user's issue limit
    active_issues_count = db.query(BookIssue).filter(
        BookIssue.user_id == current_user.id,
        BookIssue.status == IssueStatus.ACTIVE
    ).count()

    if active_issues_count >= current_user.max_books_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum issue limit reached ({current_user.max_books_allowed} books)"
        )

    # Create issue record
    issued_at = datetime.utcnow()
    due_date = issued_at + timedelta(days=14)  # 2 weeks

    db_issue = BookIssue(
        book_id=issue_request.book_id,
        user_id=current_user.id,
        issued_at=issued_at,
        due_date=due_date
    )

    # Update book availability
    book.available_copies -= 1

    db.add(db_issue)
    db.commit()
    db.refresh(db_issue)

    # Add additional info for response
    db_issue.book_title = book.title
    db_issue.user_username = current_user.username

    return db_issue


@app.post("/books/return/{issue_id}")
def return_book(issue_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    """Return a book that was issued with fine calculation."""

    issue = db.query(BookIssue).filter(
        BookIssue.id == issue_id,
        BookIssue.user_id == current_user.id,
        BookIssue.status == IssueStatus.ACTIVE
    ).first()

    if not issue:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active issue not found"
        )

    # Calculate fine for overdue books
    return_date = datetime.utcnow()
    fine_amount = 0.0

    if return_date > issue.due_date:
        overdue_days = (return_date - issue.due_date).days
        fine_amount = overdue_days * 1.0  # $1 per day fine

    # Update issue
    issue.return_date = return_date
    issue.status = IssueStatus.RETURNED
    issue.fine_amount = fine_amount

    # Update book availability
    book = db.query(Book).filter(Book.id == issue.book_id).first()
    book.available_copies += 1

    db.commit()

    return {
        "message": "Book returned successfully",
        "issue_id": issue_id,
        "return_date": return_date,
        "fine_amount": fine_amount,
        "was_overdue": fine_amount > 0
    }


@app.get("/my-issues", response_model=List[IssueResponse])
def get_my_issues(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> List[IssueResponse]:
    """Get current user's book issues"""
    issues = db.query(BookIssue).filter(
        BookIssue.user_id == current_user.id).all()

    # Add book titles
    for issue in issues:
        book = db.query(Book).filter(Book.id == issue.book_id).first()
        issue.book_title = book.title if book else "Unknown"
        issue.user_username = current_user.username

    return issues

# Admin Routes (Enhanced)


@app.get("/admin/users", response_model=List[UserResponse])
def get_all_users(admin_user: User = Depends(required_admin), db: Session = Depends(get_db)) -> List[UserResponse]:
    """Get all users (Admin only)"""
    return db.query(User).all()


@app.get("/admin/issues", response_model=List[IssueResponse])
def get_all_issues(admin_user: User = Depends(required_admin), db: Session = Depends(get_db)) -> List[IssueResponse]:
    """Get all book issues (Admin only)"""
    issues = db.query(BookIssue).all()

    # Add book and user names
    for issue in issues:
        book = db.query(Book).filter(Book.id == issue.book_id).first()
        user = db.query(User).filter(User.id == issue.user_id).first()
        issue.book_title = book.title if book else "Unknown"
        issue.user_username = user.username if user else "Unknown"

    return issues


@app.get("/admin/stats")
def get_admin_stats(admin_user: User = Depends(required_admin), db: Session = Depends(get_db)) -> dict:
    """Get admin dashboard statistics"""
    total_users = db.query(User).count()
    total_books = db.query(Book).count()
    total_issues = db.query(BookIssue).count()
    active_issues = db.query(BookIssue).filter(
        BookIssue.status == IssueStatus.ACTIVE).count()

    # Calculate overdue books
    current_time = datetime.utcnow()
    overdue_issues = db.query(BookIssue).filter(
        BookIssue.status == IssueStatus.ACTIVE,
        BookIssue.due_date < current_time
    ).count()

    # Calculate total fines collected
    total_fines = db.query(BookIssue).filter(BookIssue.fine_amount > 0).count()

    return {
        "total_users": total_users,
        "total_books": total_books,
        "total_issues": total_issues,
        "active_issues": active_issues,
        "overdue_issues": overdue_issues,
        "available_books": db.query(Book).filter(Book.available_copies > 0).count(),
        "books_with_files": db.query(Book).filter(Book.file_path.isnot(None)).count(),
        "total_fines_collected": total_fines,
        "timestamp": current_time
    }


@app.get("/admin/overdue-books")
def get_overdue_books(admin_user: User = Depends(required_admin), db: Session = Depends(get_db)) -> List[dict]:
    """Get all overdue books for admin notifications"""
    current_time = datetime.utcnow()
    overdue_issues = db.query(BookIssue).filter(
        BookIssue.status == IssueStatus.ACTIVE,
        BookIssue.due_date < current_time
    ).all()

    overdue_list = []
    for issue in overdue_issues:
        book = db.query(Book).filter(Book.id == issue.book_id).first()
        user = db.query(User).filter(User.id == issue.user_id).first()
        days_overdue = (current_time - issue.due_date).days

        overdue_list.append({
            "issue_id": issue.id,
            "book_title": book.title if book else "Unknown",
            "user_username": user.username if user else "Unknown",
            "user_email": user.email if user else "Unknown",
            "due_date": issue.due_date,
            "days_overdue": days_overdue,
            "fine_amount": days_overdue * 1.0
        })

    return overdue_list

# Health Check (Enhanced)


@app.get("/health")
def health_check(db: Session = Depends(get_db)) -> dict:
    """API health check with database connectivity"""
    try:
        # Test database connectivity
        db.execute("SELECT 1")
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    return {
        "status": "healthy",
        "version": "2.0.0",
        "database": db_status,
        "features": ["JWT Auth", "File Upload", "Database", "Role-based Access"],
        "upload_dir": UPLOAD_DIR,
        "max_file_size_mb": MAX_FILE_SIZE / 1024 / 1024,
        "allowed_extensions": list(ALLOWED_EXTENSIONS),
        "timestamp": datetime.utcnow()
    }


@app.get("/")
def root() -> dict:
    """Welcome message"""
    return {
        "message": "Library Management System API v2.0 - Enhanced",
        "docs": "/docs",
        "features": [
            "JWT Authentication",
            "Role-based Access Control",
            "File Upload & Download",
            "SQLAlchemy Database",
            "Issue Limits & Fine Calculation",
            "Admin Dashboard & Statistics",
            "Overdue Book Management"
        ],
        "version": "2.0.0"
    }


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
