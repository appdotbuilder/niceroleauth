"""Login page implementation."""

import logging
from nicegui import ui
from typing import Optional

from app.utils.auth import (
    authenticate_user,
    create_session,
    login_user,
    AuthError,
    InvalidCredentialsError,
    InactiveUserError,
)
from app.models import User

logger = logging.getLogger(__name__)


class LoginPage:
    """Login page component."""

    def __init__(self):
        self.username_input: Optional[ui.input] = None
        self.password_input: Optional[ui.input] = None
        self.login_button: Optional[ui.button] = None
        self.message_label: Optional[ui.label] = None

    def create(self):
        """Create the login page UI."""
        # Apply modern theme colors
        ui.colors(
            primary="#2563eb",
            secondary="#64748b",
            accent="#10b981",
            positive="#10b981",
            negative="#ef4444",
            warning="#f59e0b",
            info="#3b82f6",
        )

        # Main container with centered layout
        with ui.column().classes("w-full h-screen items-center justify-center bg-gray-50"):
            # Login card
            with ui.card().classes("w-96 p-8 shadow-xl rounded-xl bg-white"):
                # Header
                ui.label("Welcome Back").classes("text-3xl font-bold text-gray-800 text-center mb-2")
                ui.label("Sign in to your account").classes("text-gray-600 text-center mb-8")

                # Login form
                with ui.column().classes("w-full gap-6"):
                    # Username field
                    self.username_input = ui.input("Username").classes("w-full").props("outlined")
                    self.username_input.on("keydown.enter", self._handle_login)

                    # Password field
                    self.password_input = ui.input("Password", password=True).classes("w-full").props("outlined")
                    self.password_input.on("keydown.enter", self._handle_login)

                    # Login button
                    self.login_button = ui.button("Sign In", on_click=self._handle_login).classes(
                        "w-full py-3 text-white font-semibold rounded-lg bg-primary hover:bg-blue-600 transition-colors"
                    )

                    # Message area
                    self.message_label = ui.label().classes("text-center min-h-6")

                # Default credentials info
                with ui.expansion("Test Credentials", icon="info").classes("w-full mt-4"):
                    ui.label("Admin: admin / admin123").classes("text-sm text-gray-600")
                    ui.label("Test User: testuser / test123").classes("text-sm text-gray-600")

    def _handle_login(self):
        """Handle login form submission."""
        if self.username_input is None or self.password_input is None:
            return

        username = self.username_input.value.strip()
        password = self.password_input.value

        # Clear previous messages
        if self.message_label is not None:
            self.message_label.set_text("")
            self.message_label.classes("text-center min-h-6")

        # Validate input
        if not username or not password:
            self._show_message("Please enter both username and password", "error")
            return

        # Disable login button during authentication
        if self.login_button is not None:
            self.login_button.set_enabled(False)

        try:
            # Authenticate user
            user = authenticate_user(username, password)

            # Create session
            session_token = create_session(user)

            # Store session in client
            login_user(user, session_token)

            # Show success message
            self._show_message(f"Welcome, {user.full_name}!", "success")

            # Redirect based on user role
            self._redirect_after_login(user)

        except InvalidCredentialsError:
            self._show_message("Invalid username or password", "error")
        except InactiveUserError:
            self._show_message("Your account is inactive. Please contact support.", "error")
        except AuthError as e:
            self._show_message(f"Authentication failed: {str(e)}", "error")
        except Exception as e:
            self._show_message("An unexpected error occurred. Please try again.", "error")
            # Log the actual error for debugging
            logger.error(f"Login error: {str(e)}")
        finally:
            # Re-enable login button
            if self.login_button is not None:
                self.login_button.set_enabled(True)

    def _show_message(self, message: str, message_type: str = "info"):
        """Show a message to the user."""
        if self.message_label is None:
            return

        self.message_label.set_text(message)

        if message_type == "success":
            self.message_label.classes("text-center min-h-6 text-green-600 font-medium")
            ui.notify(message, type="positive")
        elif message_type == "error":
            self.message_label.classes("text-center min-h-6 text-red-600 font-medium")
            ui.notify(message, type="negative")
        else:
            self.message_label.classes("text-center min-h-6 text-blue-600 font-medium")
            ui.notify(message, type="info")

    def _redirect_after_login(self, user: User):
        """Redirect user after successful login based on their role."""
        # Check if user is admin
        is_admin = any(role.name == "admin" for role in user.roles)

        if is_admin:
            ui.timer(1.0, lambda: ui.navigate.to("/admin/dashboard"), once=True)
        else:
            ui.timer(1.0, lambda: ui.navigate.to("/dashboard"), once=True)


def create():
    """Create the login page route."""

    @ui.page("/login")
    def login_page():
        login_page_component = LoginPage()
        login_page_component.create()

    @ui.page("/")
    def index_page():
        # Check if user is already logged in
        from app.utils.auth import get_current_user

        current_user = get_current_user()

        if current_user is not None:
            # User is already logged in, redirect to dashboard
            is_admin = any(role.name == "admin" for role in current_user.roles)
            if is_admin:
                ui.navigate.to("/admin/dashboard")
            else:
                ui.navigate.to("/dashboard")
        else:
            # Redirect to login page
            ui.navigate.to("/login")
