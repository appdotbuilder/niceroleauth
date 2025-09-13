"""Tests for authentication utilities."""

import pytest
from datetime import datetime, timedelta

from app.utils.auth import (
    hash_password,
    verify_password,
    authenticate_user,
    create_session,
    get_user_from_session,
    invalidate_session,
    has_role,
    has_permission,
    is_admin,
    AuthError,
    InvalidCredentialsError,
    InactiveUserError,
    SessionExpiredError,
)
from app.services.user_service import UserService, RoleService, create_default_users_and_roles
from app.models import UserCreate, RoleType, PermissionType
from app.database import reset_db


@pytest.fixture()
def new_db():
    reset_db()
    create_default_users_and_roles()
    yield
    reset_db()


class TestPasswordHashing:
    """Test password hashing utilities."""

    def test_hash_password_creates_hash(self):
        password = "test123"
        hash_result = hash_password(password)

        assert hash_result is not None
        assert ":" in hash_result  # Should contain salt separator
        assert len(hash_result) > len(password)

    def test_verify_password_success(self):
        password = "test123"
        password_hash = hash_password(password)

        assert verify_password(password, password_hash)

    def test_verify_password_failure(self):
        password = "test123"
        wrong_password = "wrong123"
        password_hash = hash_password(password)

        assert not verify_password(wrong_password, password_hash)

    def test_verify_password_invalid_hash_format(self):
        password = "test123"
        invalid_hash = "invalid_hash_format"

        assert not verify_password(password, invalid_hash)


class TestUserAuthentication:
    """Test user authentication."""

    def test_authenticate_user_success(self, new_db):
        user = authenticate_user("admin", "admin123")

        assert user is not None
        assert user.username == "admin"
        assert user.last_login is not None

    def test_authenticate_user_invalid_username(self, new_db):
        with pytest.raises(InvalidCredentialsError):
            authenticate_user("nonexistent", "password")

    def test_authenticate_user_invalid_password(self, new_db):
        with pytest.raises(InvalidCredentialsError):
            authenticate_user("admin", "wrongpassword")

    def test_authenticate_inactive_user(self, new_db):
        # Create inactive user
        user_data = UserCreate(
            username="inactive", email="inactive@example.com", password="password123", full_name="Inactive User"
        )
        user = UserService.create_user(user_data)

        # Deactivate user
        from app.database import get_session

        with get_session() as session:
            user.is_active = False
            session.add(user)
            session.commit()

        with pytest.raises(InactiveUserError):
            authenticate_user("inactive", "password123")


class TestSessionManagement:
    """Test session management."""

    def test_create_session(self, new_db):
        user = authenticate_user("admin", "admin123")
        session_token = create_session(user)

        assert session_token is not None
        assert len(session_token) > 20  # Should be a reasonably long token

    def test_get_user_from_session_success(self, new_db):
        user = authenticate_user("admin", "admin123")
        session_token = create_session(user)

        retrieved_user = get_user_from_session(session_token)

        assert retrieved_user is not None
        assert retrieved_user.id == user.id
        assert retrieved_user.username == user.username

    def test_get_user_from_session_invalid_token(self, new_db):
        result = get_user_from_session("invalid_token")
        assert result is None

    def test_get_user_from_session_expired(self, new_db):
        user = authenticate_user("admin", "admin123")

        # Create expired session manually
        from app.database import get_session
        from app.models import UserSession
        from app.utils.auth import generate_session_token

        if user.id is not None:
            with get_session() as session:
                session_token = generate_session_token()
                expired_session = UserSession(
                    user_id=user.id,
                    session_token=session_token,
                    expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired
                )
                session.add(expired_session)
                session.commit()

            with pytest.raises(SessionExpiredError):
                get_user_from_session(session_token)

    def test_invalidate_session(self, new_db):
        user = authenticate_user("admin", "admin123")
        session_token = create_session(user)

        # Session should be valid initially
        retrieved_user = get_user_from_session(session_token)
        assert retrieved_user is not None

        # Invalidate session
        result = invalidate_session(session_token)
        assert result is True

        # Session should no longer be valid
        retrieved_user = get_user_from_session(session_token)
        assert retrieved_user is None


class TestRoleBasedAccess:
    """Test role-based access control."""

    def test_has_role_admin(self, new_db):
        user = authenticate_user("admin", "admin123")
        assert has_role(user, "admin")
        assert not has_role(user, "nonexistent_role")

    def test_has_role_regular_user(self, new_db):
        user = authenticate_user("testuser", "test123")
        assert has_role(user, "user")
        assert not has_role(user, "admin")

    def test_has_permission_admin(self, new_db):
        user = authenticate_user("admin", "admin123")

        # Admin should have all permissions
        assert has_permission(user, PermissionType.READ)
        assert has_permission(user, PermissionType.WRITE)
        assert has_permission(user, PermissionType.DELETE)
        assert has_permission(user, PermissionType.ADMIN)

    def test_has_permission_regular_user(self, new_db):
        user = authenticate_user("testuser", "test123")

        # Regular user should have basic permissions
        assert has_permission(user, PermissionType.READ)
        assert has_permission(user, PermissionType.WRITE)
        # Regular user should not have admin permissions
        assert not has_permission(user, PermissionType.DELETE)
        assert not has_permission(user, PermissionType.ADMIN)

    def test_is_admin(self, new_db):
        admin_user = authenticate_user("admin", "admin123")
        regular_user = authenticate_user("testuser", "test123")

        assert is_admin(admin_user)
        assert not is_admin(regular_user)


class TestErrorHandling:
    """Test error handling in authentication."""

    def test_auth_error_inheritance(self):
        """Test that specific auth errors inherit from AuthError."""
        assert issubclass(InvalidCredentialsError, AuthError)
        assert issubclass(InactiveUserError, AuthError)
        assert issubclass(SessionExpiredError, AuthError)

    def test_invalid_credentials_error_message(self, new_db):
        """Test error message for invalid credentials."""
        try:
            authenticate_user("nonexistent", "password")
            assert False, "Should have raised InvalidCredentialsError"
        except InvalidCredentialsError as e:
            assert "Invalid username or password" in str(e)

    def test_inactive_user_error_message(self, new_db):
        """Test error message for inactive user."""
        # Create and deactivate user
        user_data = UserCreate(
            username="inactive_test",
            email="inactive_test@example.com",
            password="password123",
            full_name="Inactive Test User",
        )
        user = UserService.create_user(user_data)

        from app.database import get_session

        with get_session() as session:
            user.is_active = False
            session.add(user)
            session.commit()

        try:
            authenticate_user("inactive_test", "password123")
            assert False, "Should have raised InactiveUserError"
        except InactiveUserError as e:
            assert "inactive" in str(e).lower()


class TestDefaultUsersAndRoles:
    """Test default users and roles creation."""

    def test_default_admin_user_created(self, new_db):
        user = UserService.get_user_by_username("admin")

        assert user is not None
        assert user.username == "admin"
        assert user.email == "admin@example.com"
        assert user.full_name == "System Administrator"
        assert user.is_active

    def test_default_test_user_created(self, new_db):
        user = UserService.get_user_by_username("testuser")

        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.is_active

    def test_default_roles_created(self, new_db):
        admin_role = RoleService.get_role_by_name("admin")
        user_role = RoleService.get_role_by_name("user")

        assert admin_role is not None
        assert admin_role.role_type == RoleType.ADMIN
        assert user_role is not None
        assert user_role.role_type == RoleType.USER

    def test_role_assignments(self, new_db):
        # Admin user should have admin role
        admin_role_names = UserService.get_user_roles("admin")
        assert "admin" in admin_role_names

        # Test user should have user role
        user_role_names = UserService.get_user_roles("testuser")
        assert "user" in user_role_names
