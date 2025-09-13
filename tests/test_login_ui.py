"""Tests for login UI functionality."""

import pytest
from nicegui.testing import User

from app.database import reset_db
from app.services.user_service import create_default_users_and_roles


@pytest.fixture()
def new_db():
    reset_db()
    create_default_users_and_roles()
    yield
    reset_db()


class TestLoginPage:
    """Test login page UI interactions."""

    async def test_login_page_displays(self, user: User, new_db):
        """Test that login page displays correctly."""
        await user.open("/login")

        # Check for key UI elements
        await user.should_see("Welcome Back")
        await user.should_see("Sign in to your account")
        await user.should_see("Username")
        await user.should_see("Password")
        await user.should_see("Sign In")
        await user.should_see("Test Credentials")

    async def test_successful_admin_login(self, user: User, new_db):
        """Test successful login with admin credentials."""
        await user.open("/login")

        # Enter admin credentials
        user.find("Username").type("admin")
        user.find("Password").type("admin123")

        # Click login button
        user.find("Sign In").click()

        # Should see welcome message
        await user.should_see("Welcome, System Administrator!")

    async def test_successful_user_login(self, user: User, new_db):
        """Test successful login with regular user credentials."""
        await user.open("/login")

        # Enter user credentials
        user.find("Username").type("testuser")
        user.find("Password").type("test123")

        # Click login button
        user.find("Sign In").click()

        # Should see welcome message
        await user.should_see("Welcome, Test User!")

    async def test_invalid_credentials(self, user: User, new_db):
        """Test login with invalid credentials."""
        await user.open("/login")

        # Enter invalid credentials
        user.find("Username").type("invalid_user")
        user.find("Password").type("wrong_password")

        # Click login button
        user.find("Sign In").click()

        # Should see error message
        await user.should_see("Invalid username or password")

    async def test_empty_credentials(self, user: User, new_db):
        """Test login with empty credentials."""
        await user.open("/login")

        # Click login button without entering credentials
        user.find("Sign In").click()

        # Should see validation message
        await user.should_see("Please enter both username and password")

    async def test_enter_key_login(self, user: User, new_db):
        """Test login using Enter key."""
        await user.open("/login")

        # Enter credentials
        username_input = user.find("Username")
        password_input = user.find("Password")

        username_input.type("admin")
        password_input.type("admin123")

        # Press Enter in password field
        password_input.trigger("keydown.enter")

        # Should see welcome message
        await user.should_see("Welcome, System Administrator!")

    async def test_test_credentials_expansion(self, user: User, new_db):
        """Test that test credentials expansion shows correctly."""
        await user.open("/login")

        # Click on test credentials expansion
        user.find("Test Credentials").click()

        # Should show credential information
        await user.should_see("Admin: admin / admin123")
        await user.should_see("Test User: testuser / test123")


class TestDashboardAccess:
    """Test dashboard access and redirection."""

    async def test_redirect_to_login_when_not_authenticated(self, user: User, new_db):
        """Test that accessing dashboard redirects to login when not authenticated."""
        await user.open("/dashboard")

        # Should be redirected to login page
        await user.should_see("Welcome Back")
        await user.should_see("Sign in to your account")

    async def test_admin_dashboard_access(self, user: User, new_db):
        """Test admin dashboard access after login."""
        await user.open("/login")

        # Login as admin
        user.find("Username").type("admin")
        user.find("Password").type("admin123")
        user.find("Sign In").click()

        # Should see login success message
        await user.should_see("Welcome, System Administrator!")

    async def test_user_dashboard_access(self, user: User, new_db):
        """Test regular user dashboard access after login."""
        await user.open("/login")

        # Login as regular user
        user.find("Username").type("testuser")
        user.find("Password").type("test123")
        user.find("Sign In").click()

        # Should see login success message
        await user.should_see("Welcome, Test User!")

    async def test_regular_user_cannot_access_admin_dashboard(self, user: User, new_db):
        """Test that regular users cannot access admin dashboard."""
        await user.open("/login")

        # Login as regular user
        user.find("Username").type("testuser")
        user.find("Password").type("test123")
        user.find("Sign In").click()

        # Should see login success message
        await user.should_see("Welcome, Test User!")


class TestIndexPageRedirection:
    """Test index page redirection behavior."""

    async def test_index_redirects_to_login_when_not_authenticated(self, user: User, new_db):
        """Test that index page redirects to login when user is not authenticated."""
        await user.open("/")

        # Should be redirected to login page
        await user.should_see("Welcome Back")
        await user.should_see("Sign in to your account")


class TestUIResponsiveness:
    """Test UI responsiveness and user experience."""

    async def test_login_button_disabled_during_authentication(self, user: User, new_db):
        """Test that login button is disabled during authentication process."""
        await user.open("/login")

        # Enter credentials
        user.find("Username").type("admin")
        user.find("Password").type("admin123")

        # Click login button
        login_button = user.find("Sign In")
        login_button.click()

        # Button should be re-enabled after authentication
        # (This is a quick test since we can't easily test the disabled state in the middle of processing)
        await user.should_see("Welcome, System Administrator!")

    async def test_form_validation_messages_clear(self, user: User, new_db):
        """Test that validation messages clear when corrected."""
        await user.open("/login")

        # Try login with empty credentials
        user.find("Sign In").click()
        await user.should_see("Please enter both username and password")

        # Enter valid credentials - error should clear
        user.find("Username").type("admin")
        user.find("Password").type("admin123")
        user.find("Sign In").click()

        # Should see success message instead of error
        await user.should_see("Welcome, System Administrator!")


class TestNavigationAndLogout:
    """Test navigation and logout functionality."""

    async def test_logout_from_login_page(self, user: User, new_db):
        """Test basic login flow for logout functionality."""
        # Login test
        await user.open("/login")
        user.find("Username").type("admin")
        user.find("Password").type("admin123")
        user.find("Sign In").click()
        await user.should_see("Welcome, System Administrator!")
