from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime
from typing import Optional, List
from enum import Enum


# Enums for role types and permissions
class RoleType(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class PermissionType(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


# Association table for many-to-many relationship between User and Role
class UserRole(SQLModel, table=True):
    __tablename__ = "user_roles"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    role_id: int = Field(foreign_key="roles.id", index=True)
    assigned_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    user: "User" = Relationship(back_populates="user_roles")
    role: "Role" = Relationship(back_populates="user_roles")


# Association table for many-to-many relationship between Role and Permission
class RolePermission(SQLModel, table=True):
    __tablename__ = "role_permissions"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(foreign_key="roles.id", index=True)
    permission_type: PermissionType = Field(index=True)
    resource: str = Field(max_length=100, default="*")  # Resource this permission applies to
    granted_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    role: "Role" = Relationship(back_populates="role_permissions")


# Persistent models (stored in database)
class User(SQLModel, table=True):
    __tablename__ = "users"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, max_length=50, index=True)
    email: str = Field(unique=True, max_length=255, regex=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password_hash: str = Field(max_length=255)  # Will store hashed password
    full_name: str = Field(max_length=100)
    is_active: bool = Field(default=True, index=True)
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = Field(default=None)

    # Relationships
    user_roles: List["UserRole"] = Relationship(back_populates="user")
    sessions: List["UserSession"] = Relationship(back_populates="user")

    # Helper property to get roles directly
    @property
    def roles(self) -> List["Role"]:
        return [user_role.role for user_role in self.user_roles]


class Role(SQLModel, table=True):
    __tablename__ = "roles"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, max_length=50, index=True)
    display_name: str = Field(max_length=100)
    description: str = Field(max_length=255, default="")
    role_type: RoleType = Field(index=True)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    user_roles: List["UserRole"] = Relationship(back_populates="role")
    role_permissions: List["RolePermission"] = Relationship(back_populates="role")

    # Helper property to get permissions directly
    @property
    def permissions(self) -> List["RolePermission"]:
        return self.role_permissions


class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    session_token: str = Field(unique=True, max_length=255, index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True, index=True)
    ip_address: Optional[str] = Field(max_length=45, default=None)  # Support IPv6
    user_agent: Optional[str] = Field(max_length=500, default=None)

    # Relationships
    user: "User" = Relationship(back_populates="sessions")


# Non-persistent schemas (for validation, forms, API requests/responses)
class UserCreate(SQLModel, table=False):
    username: str = Field(max_length=50)
    email: str = Field(max_length=255)
    password: str = Field(min_length=6, max_length=100)  # Plain password, will be hashed
    full_name: str = Field(max_length=100)


class UserUpdate(SQLModel, table=False):
    username: Optional[str] = Field(default=None, max_length=50)
    email: Optional[str] = Field(default=None, max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=100)
    is_active: Optional[bool] = Field(default=None)
    is_verified: Optional[bool] = Field(default=None)


class UserLogin(SQLModel, table=False):
    username: str = Field(max_length=50)
    password: str = Field(max_length=100)


class UserResponse(SQLModel, table=False):
    id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    created_at: str  # ISO format string
    last_login: Optional[str] = None  # ISO format string
    roles: List[str] = []  # List of role names


class RoleCreate(SQLModel, table=False):
    name: str = Field(max_length=50)
    display_name: str = Field(max_length=100)
    description: str = Field(default="", max_length=255)
    role_type: RoleType


class RoleUpdate(SQLModel, table=False):
    display_name: Optional[str] = Field(default=None, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    is_active: Optional[bool] = Field(default=None)


class RoleResponse(SQLModel, table=False):
    id: int
    name: str
    display_name: str
    description: str
    role_type: RoleType
    is_active: bool
    created_at: str  # ISO format string
    permissions: List[str] = []  # List of permission types


class PasswordChange(SQLModel, table=False):
    current_password: str = Field(max_length=100)
    new_password: str = Field(min_length=6, max_length=100)


class UserRoleAssignment(SQLModel, table=False):
    user_id: int
    role_id: int


class RolePermissionAssignment(SQLModel, table=False):
    role_id: int
    permission_type: PermissionType
    resource: str = Field(default="*", max_length=100)


class SessionCreate(SQLModel, table=False):
    user_id: int
    expires_at: datetime
    ip_address: Optional[str] = Field(default=None, max_length=45)
    user_agent: Optional[str] = Field(default=None, max_length=500)


class SessionResponse(SQLModel, table=False):
    id: int
    session_token: str
    expires_at: str  # ISO format string
    created_at: str  # ISO format string
    is_active: bool
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
