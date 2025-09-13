"""User management service."""

from typing import List, Optional

from sqlmodel import select

from app.database import get_session
from app.models import User, Role, UserRole, RolePermission, UserCreate, RoleType, PermissionType
from app.utils.auth import hash_password


class UserService:
    """Service for user management operations."""

    @staticmethod
    def create_user(user_data: UserCreate) -> User:
        """
        Create a new user.

        Args:
            user_data: User creation data

        Returns:
            Created user
        """
        with get_session() as session:
            password_hash = hash_password(user_data.password)

            user = User(
                username=user_data.username,
                email=user_data.email,
                password_hash=password_hash,
                full_name=user_data.full_name,
            )

            session.add(user)
            session.commit()
            session.refresh(user)

            return user

    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to search for

        Returns:
            User if found, None otherwise
        """
        with get_session() as session:
            statement = select(User).where(User.username == username)
            return session.exec(statement).first()

    @staticmethod
    def get_user_roles(username: str) -> List[str]:
        """
        Get role names for a user.

        Args:
            username: Username to search for

        Returns:
            List of role names
        """
        with get_session() as session:
            statement = select(User).where(User.username == username)
            user = session.exec(statement).first()

            if user is None or user.id is None:
                return []

            # Query user roles with joins
            user_roles_stmt = select(Role.name).select_from(Role).join(UserRole).where(UserRole.user_id == user.id)
            role_names = session.exec(user_roles_stmt).all()
            return list(role_names)

    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[User]:
        """
        Get user by ID.

        Args:
            user_id: User ID to search for

        Returns:
            User if found, None otherwise
        """
        with get_session() as session:
            return session.get(User, user_id)

    @staticmethod
    def assign_role_to_user(user_id: int, role_id: int) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: ID of the user
            role_id: ID of the role

        Returns:
            True if role was assigned, False if already assigned
        """
        with get_session() as session:
            # Check if assignment already exists
            statement = select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
            existing = session.exec(statement).first()

            if existing is not None:
                return False

            user_role = UserRole(user_id=user_id, role_id=role_id)
            session.add(user_role)
            session.commit()

            return True


class RoleService:
    """Service for role management operations."""

    @staticmethod
    def create_role(name: str, display_name: str, role_type: RoleType, description: str = "") -> Role:
        """
        Create a new role.

        Args:
            name: Role name (unique)
            display_name: Human-readable role name
            role_type: Type of role
            description: Role description

        Returns:
            Created role
        """
        with get_session() as session:
            role = Role(name=name, display_name=display_name, role_type=role_type, description=description)

            session.add(role)
            session.commit()
            session.refresh(role)

            return role

    @staticmethod
    def get_role_by_name(name: str) -> Optional[Role]:
        """
        Get role by name.

        Args:
            name: Role name to search for

        Returns:
            Role if found, None otherwise
        """
        with get_session() as session:
            statement = select(Role).where(Role.name == name)
            return session.exec(statement).first()

    @staticmethod
    def assign_permission_to_role(role_id: int, permission_type: PermissionType, resource: str = "*") -> bool:
        """
        Assign a permission to a role.

        Args:
            role_id: ID of the role
            permission_type: Permission to assign
            resource: Resource the permission applies to

        Returns:
            True if permission was assigned, False if already assigned
        """
        with get_session() as session:
            # Check if permission already exists
            statement = select(RolePermission).where(
                RolePermission.role_id == role_id,
                RolePermission.permission_type == permission_type,
                RolePermission.resource == resource,
            )
            existing = session.exec(statement).first()

            if existing is not None:
                return False

            role_permission = RolePermission(role_id=role_id, permission_type=permission_type, resource=resource)

            session.add(role_permission)
            session.commit()

            return True


def create_default_users_and_roles():
    """Create default users and roles for the application."""
    with get_session() as session:
        # Create admin role if it doesn't exist
        admin_role = session.exec(select(Role).where(Role.name == "admin")).first()
        if admin_role is None:
            admin_role = RoleService.create_role(
                name="admin", display_name="Administrator", role_type=RoleType.ADMIN, description="Full system access"
            )

            # Assign all permissions to admin role
            if admin_role.id is not None:
                for permission in PermissionType:
                    RoleService.assign_permission_to_role(admin_role.id, permission)

        # Create user role if it doesn't exist
        user_role = session.exec(select(Role).where(Role.name == "user")).first()
        if user_role is None:
            user_role = RoleService.create_role(
                name="user", display_name="Regular User", role_type=RoleType.USER, description="Basic system access"
            )

            # Assign basic permissions to user role
            if user_role.id is not None:
                RoleService.assign_permission_to_role(user_role.id, PermissionType.READ)
                RoleService.assign_permission_to_role(user_role.id, PermissionType.WRITE)

        # Create admin user if it doesn't exist
        admin_user = UserService.get_user_by_username("admin")
        if admin_user is None:
            admin_user_data = UserCreate(
                username="admin", email="admin@example.com", password="admin123", full_name="System Administrator"
            )
            admin_user = UserService.create_user(admin_user_data)
            if admin_user.id is not None and admin_role.id is not None:
                UserService.assign_role_to_user(admin_user.id, admin_role.id)

        # Create test user if it doesn't exist
        test_user = UserService.get_user_by_username("testuser")
        if test_user is None:
            test_user_data = UserCreate(
                username="testuser", email="test@example.com", password="test123", full_name="Test User"
            )
            test_user = UserService.create_user(test_user_data)
            if test_user.id is not None and user_role.id is not None:
                UserService.assign_role_to_user(test_user.id, user_role.id)
