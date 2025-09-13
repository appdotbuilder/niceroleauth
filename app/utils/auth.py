"""Authentication utilities for user login, session management, and RBAC."""

import hashlib
import logging
import secrets
from datetime import datetime
from typing import Optional

from sqlmodel import select
from nicegui import app

from app.database import get_session
from app.models import User, Role, UserSession, UserRole, RolePermission, PermissionType
from app.config import Config

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Base exception for authentication errors."""

    pass


class InvalidCredentialsError(AuthError):
    """Raised when login credentials are invalid."""

    pass


class InactiveUserError(AuthError):
    """Raised when user account is inactive."""

    pass


class SessionExpiredError(AuthError):
    """Raised when user session has expired."""

    pass


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with salt."""
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt + Config.SECRET_KEY).encode()).hexdigest()
    return f"{salt}:{password_hash}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, hash_value = password_hash.split(":", 1)
        expected_hash = hashlib.sha256((password + salt + Config.SECRET_KEY).encode()).hexdigest()
        return secrets.compare_digest(hash_value, expected_hash)
    except ValueError as e:
        logger.warning(f"Invalid password hash format: {e}")
        return False


def generate_session_token() -> str:
    """Generate a secure session token."""
    return secrets.token_urlsafe(32)


def authenticate_user(username: str, password: str) -> User:
    """
    Authenticate a user with username and password.

    Args:
        username: User's username
        password: User's plain text password

    Returns:
        User object if authentication successful

    Raises:
        InvalidCredentialsError: If credentials are invalid
        InactiveUserError: If user account is inactive
    """
    with get_session() as session:
        # Find user by username
        statement = select(User).where(User.username == username)
        user = session.exec(statement).first()

        if user is None or not verify_password(password, user.password_hash):
            raise InvalidCredentialsError("Invalid username or password")

        if not user.is_active:
            raise InactiveUserError("User account is inactive")

        # Update last login time
        user.last_login = datetime.utcnow()
        session.add(user)
        session.commit()
        session.refresh(user)

        return user


def create_session(user: User, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> str:
    """
    Create a new user session.

    Args:
        user: User to create session for
        ip_address: Client IP address (optional)
        user_agent: Client user agent (optional)

    Returns:
        Session token
    """
    if user.id is None:
        raise ValueError("User ID cannot be None")

    with get_session() as session:
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + Config.get_session_duration()

        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        session.add(user_session)
        session.commit()

        return session_token


def get_user_from_session(session_token: str) -> Optional[User]:
    """
    Get user from session token.

    Args:
        session_token: Session token

    Returns:
        User object if session is valid, None otherwise

    Raises:
        SessionExpiredError: If session has expired
    """
    with get_session() as session:
        statement = select(UserSession).where(
            UserSession.session_token == session_token,
            UserSession.is_active == True,  # noqa: E712
        )
        user_session = session.exec(statement).first()

        if user_session is None:
            return None

        # Check if session has expired
        if user_session.expires_at < datetime.utcnow():
            user_session.is_active = False
            session.add(user_session)
            session.commit()
            raise SessionExpiredError("Session has expired")

        # Get user
        statement = select(User).where(User.id == user_session.user_id)
        user = session.exec(statement).first()

        return user


def invalidate_session(session_token: str) -> bool:
    """
    Invalidate a user session (logout).

    Args:
        session_token: Session token to invalidate

    Returns:
        True if session was invalidated, False if not found
    """
    with get_session() as session:
        statement = select(UserSession).where(UserSession.session_token == session_token)
        user_session = session.exec(statement).first()

        if user_session is None:
            return False

        user_session.is_active = False
        session.add(user_session)
        session.commit()

        return True


def get_current_user() -> Optional[User]:
    """
    Get currently logged in user from NiceGUI app storage.

    Returns:
        Current user if logged in, None otherwise
    """
    session_token = app.storage.client.get("session_token")
    if session_token is None:
        return None

    try:
        return get_user_from_session(session_token)
    except SessionExpiredError:
        logger.info(f"Session expired for token: {session_token[:8]}...")
        # Clear expired session from client storage
        app.storage.client.pop("session_token", None)
        return None


def login_user(user: User, session_token: str) -> None:
    """
    Store user session in NiceGUI app storage.

    Args:
        user: User to log in
        session_token: Session token
    """
    app.storage.client["session_token"] = session_token
    app.storage.client["user_id"] = user.id
    app.storage.client["username"] = user.username


def logout_user() -> bool:
    """
    Log out current user.

    Returns:
        True if user was logged out, False if no user was logged in
    """
    session_token = app.storage.client.get("session_token")
    if session_token is None:
        return False

    # Clear client storage
    app.storage.client.pop("session_token", None)
    app.storage.client.pop("user_id", None)
    app.storage.client.pop("username", None)

    # Invalidate server-side session
    return invalidate_session(session_token)


def require_auth():
    """
    Decorator/function to require authentication.
    Raises AuthError if user is not authenticated.
    """
    user = get_current_user()
    if user is None:
        raise AuthError("Authentication required")
    return user


def has_role(user: User, role_name: str) -> bool:
    """
    Check if user has a specific role.

    Args:
        user: User to check
        role_name: Name of the role to check

    Returns:
        True if user has the role, False otherwise
    """
    if user.id is None:
        return False

    with get_session() as session:
        # Query user roles directly to avoid detached instance issues
        user_roles_stmt = select(Role.name).select_from(Role).join(UserRole).where(UserRole.user_id == user.id)
        role_names = session.exec(user_roles_stmt).all()
        return role_name in role_names


def has_permission(user: User, permission: PermissionType, resource: str = "*") -> bool:
    """
    Check if user has a specific permission on a resource.

    Args:
        user: User to check
        permission: Permission type to check
        resource: Resource to check permission for (default: "*" for all)

    Returns:
        True if user has the permission, False otherwise
    """
    if user.id is None:
        return False

    with get_session() as session:
        # Query permissions directly to avoid detached instance issues
        permissions_stmt = (
            select(RolePermission)
            .select_from(RolePermission)
            .join(Role)
            .join(UserRole)
            .where(
                UserRole.user_id == user.id,
                Role.is_active == True,  # noqa: E712
                RolePermission.permission_type == permission,
                (RolePermission.resource == "*") | (RolePermission.resource == resource),
            )
        )
        permissions = session.exec(permissions_stmt).all()
        return len(permissions) > 0


def is_admin(user: User) -> bool:
    """
    Check if user is an admin.

    Args:
        user: User to check

    Returns:
        True if user is admin, False otherwise
    """
    return has_role(user, "admin") or has_permission(user, PermissionType.ADMIN)


def require_role(role_name: str):
    """
    Require user to have a specific role.

    Args:
        role_name: Required role name

    Raises:
        AuthError: If user doesn't have the required role
    """
    user = require_auth()
    if not has_role(user, role_name):
        raise AuthError(f"Role '{role_name}' required")
    return user


def require_permission(permission: PermissionType, resource: str = "*"):
    """
    Require user to have a specific permission.

    Args:
        permission: Required permission
        resource: Resource permission applies to

    Raises:
        AuthError: If user doesn't have the required permission
    """
    user = require_auth()
    if not has_permission(user, permission, resource):
        raise AuthError(f"Permission '{permission}' required for resource '{resource}'")
    return user
