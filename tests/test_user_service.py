"""Tests for user management services."""

import pytest
from sqlmodel import select

from app.services.user_service import UserService, RoleService
from app.models import UserCreate, User, Role, UserRole, RolePermission, RoleType, PermissionType
from app.database import reset_db, get_session


@pytest.fixture()
def new_db():
    reset_db()
    yield
    reset_db()


class TestUserService:
    """Test user management service."""

    def test_create_user(self, new_db):
        user_data = UserCreate(
            username="newuser", email="newuser@example.com", password="password123", full_name="New User"
        )

        user = UserService.create_user(user_data)

        assert user is not None
        assert user.id is not None
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.is_active
        assert not user.is_verified
        assert user.password_hash != "password123"  # Should be hashed
        assert user.created_at is not None

    def test_get_user_by_username_exists(self, new_db):
        # Create user first
        user_data = UserCreate(
            username="testuser", email="test@example.com", password="password123", full_name="Test User"
        )
        created_user = UserService.create_user(user_data)

        # Retrieve user
        retrieved_user = UserService.get_user_by_username("testuser")

        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.username == "testuser"

    def test_get_user_by_username_not_exists(self, new_db):
        result = UserService.get_user_by_username("nonexistent")
        assert result is None

    def test_get_user_by_id_exists(self, new_db):
        # Create user first
        user_data = UserCreate(
            username="testuser", email="test@example.com", password="password123", full_name="Test User"
        )
        created_user = UserService.create_user(user_data)

        # Retrieve user
        if created_user.id is not None:
            retrieved_user = UserService.get_user_by_id(created_user.id)

            assert retrieved_user is not None
            assert retrieved_user.id == created_user.id
            assert retrieved_user.username == "testuser"

    def test_get_user_by_id_not_exists(self, new_db):
        result = UserService.get_user_by_id(999999)
        assert result is None

    def test_assign_role_to_user_success(self, new_db):
        # Create user and role
        user_data = UserCreate(
            username="testuser", email="test@example.com", password="password123", full_name="Test User"
        )
        user = UserService.create_user(user_data)

        role = RoleService.create_role(
            name="testrole", display_name="Test Role", role_type=RoleType.USER, description="A test role"
        )

        # Assign role
        if user.id is not None and role.id is not None:
            result = UserService.assign_role_to_user(user.id, role.id)
            assert result is True

            # Verify assignment
            with get_session() as session:
                statement = select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
                user_role = session.exec(statement).first()
                assert user_role is not None

    def test_assign_role_to_user_duplicate(self, new_db):
        # Create user and role
        user_data = UserCreate(
            username="testuser", email="test@example.com", password="password123", full_name="Test User"
        )
        user = UserService.create_user(user_data)

        role = RoleService.create_role(name="testrole", display_name="Test Role", role_type=RoleType.USER)

        # Assign role twice
        if user.id is not None and role.id is not None:
            result1 = UserService.assign_role_to_user(user.id, role.id)
            result2 = UserService.assign_role_to_user(user.id, role.id)

            assert result1 is True
            assert result2 is False  # Should fail on duplicate


class TestRoleService:
    """Test role management service."""

    def test_create_role(self, new_db):
        role = RoleService.create_role(
            name="testrole", display_name="Test Role", role_type=RoleType.USER, description="A test role"
        )

        assert role is not None
        assert role.id is not None
        assert role.name == "testrole"
        assert role.display_name == "Test Role"
        assert role.role_type == RoleType.USER
        assert role.description == "A test role"
        assert role.is_active
        assert role.created_at is not None

    def test_get_role_by_name_exists(self, new_db):
        # Create role first
        created_role = RoleService.create_role(name="testrole", display_name="Test Role", role_type=RoleType.USER)

        # Retrieve role
        retrieved_role = RoleService.get_role_by_name("testrole")

        assert retrieved_role is not None
        assert retrieved_role.id == created_role.id
        assert retrieved_role.name == "testrole"

    def test_get_role_by_name_not_exists(self, new_db):
        result = RoleService.get_role_by_name("nonexistent")
        assert result is None

    def test_assign_permission_to_role_success(self, new_db):
        # Create role
        role = RoleService.create_role(name="testrole", display_name="Test Role", role_type=RoleType.USER)

        # Assign permission
        if role.id is not None:
            result = RoleService.assign_permission_to_role(role.id, PermissionType.READ, "test_resource")
            assert result is True

            # Verify assignment
            with get_session() as session:
                statement = select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_type == PermissionType.READ,
                    RolePermission.resource == "test_resource",
                )
                role_permission = session.exec(statement).first()
                assert role_permission is not None

    def test_assign_permission_to_role_duplicate(self, new_db):
        # Create role
        role = RoleService.create_role(name="testrole", display_name="Test Role", role_type=RoleType.USER)

        # Assign permission twice
        if role.id is not None:
            result1 = RoleService.assign_permission_to_role(role.id, PermissionType.READ, "test_resource")
            result2 = RoleService.assign_permission_to_role(role.id, PermissionType.READ, "test_resource")

            assert result1 is True
            assert result2 is False  # Should fail on duplicate

    def test_assign_permission_default_resource(self, new_db):
        # Create role
        role = RoleService.create_role(name="testrole", display_name="Test Role", role_type=RoleType.USER)

        # Assign permission with default resource
        if role.id is not None:
            result = RoleService.assign_permission_to_role(role.id, PermissionType.WRITE)
            assert result is True

            # Verify assignment with wildcard resource
            with get_session() as session:
                statement = select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_type == PermissionType.WRITE,
                    RolePermission.resource == "*",
                )
                role_permission = session.exec(statement).first()
                assert role_permission is not None


class TestUserRoleRelationships:
    """Test user-role relationships and properties."""

    def test_user_roles_property(self, new_db):
        # Create user and roles
        user_data = UserCreate(
            username="testuser", email="test@example.com", password="password123", full_name="Test User"
        )
        user = UserService.create_user(user_data)

        role1 = RoleService.create_role("role1", "Role 1", RoleType.USER)
        role2 = RoleService.create_role("role2", "Role 2", RoleType.USER)

        # Assign roles
        if user.id is not None and role1.id is not None and role2.id is not None:
            UserService.assign_role_to_user(user.id, role1.id)
            UserService.assign_role_to_user(user.id, role2.id)

            # Refresh user to get updated relationships
            with get_session() as session:
                updated_user = session.get(User, user.id)
                if updated_user is not None:
                    # Test roles property
                    role_names = [role.name for role in updated_user.roles]
                    assert "role1" in role_names
                    assert "role2" in role_names
                    assert len(updated_user.roles) == 2

    def test_role_permissions_property(self, new_db):
        # Create role
        role = RoleService.create_role("testrole", "Test Role", RoleType.USER)

        # Assign permissions
        if role.id is not None:
            RoleService.assign_permission_to_role(role.id, PermissionType.READ)
            RoleService.assign_permission_to_role(role.id, PermissionType.WRITE)

            # Refresh role to get updated relationships
            with get_session() as session:
                updated_role = session.get(Role, role.id)
                if updated_role is not None:
                    # Test permissions property
                    permission_types = [perm.permission_type for perm in updated_role.permissions]
                    assert PermissionType.READ in permission_types
                    assert PermissionType.WRITE in permission_types
                    assert len(updated_role.permissions) == 2


class TestDataValidation:
    """Test data validation in services."""

    def test_unique_username_constraint(self, new_db):
        # Create first user
        user_data1 = UserCreate(
            username="uniqueuser", email="user1@example.com", password="password123", full_name="User 1"
        )
        UserService.create_user(user_data1)

        # Try to create second user with same username
        user_data2 = UserCreate(
            username="uniqueuser",  # Same username
            email="user2@example.com",
            password="password123",
            full_name="User 2",
        )

        # This should raise an exception due to unique constraint
        with pytest.raises(Exception):  # Could be IntegrityError or similar
            UserService.create_user(user_data2)

    def test_unique_role_name_constraint(self, new_db):
        # Create first role
        RoleService.create_role("uniquerole", "Unique Role 1", RoleType.USER)

        # Try to create second role with same name
        with pytest.raises(Exception):  # Could be IntegrityError or similar
            RoleService.create_role("uniquerole", "Unique Role 2", RoleType.USER)
