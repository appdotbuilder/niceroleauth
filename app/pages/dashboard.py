"""Dashboard pages for authenticated users."""

import logging
from nicegui import ui

from app.utils.auth import logout_user, require_auth, is_admin, AuthError
from app.models import User

logger = logging.getLogger(__name__)


class DashboardNavbar:
    """Navigation bar component for dashboard."""

    def __init__(self, user: User):
        self.user = user

    def create(self):
        """Create the navigation bar."""
        with ui.header().classes("bg-primary text-white px-6 py-4 shadow-lg"):
            with ui.row().classes("w-full items-center justify-between"):
                # Left side - App title
                ui.label("NiceGUI Auth App").classes("text-xl font-bold")

                # Right side - User info and logout
                with ui.row().classes("items-center gap-4"):
                    ui.label(f"Welcome, {self.user.full_name}").classes("text-white")
                    ui.button("Logout", on_click=self._handle_logout, icon="logout").classes(
                        "bg-red-500 hover:bg-red-600 text-white"
                    ).props("outline")

    def _handle_logout(self):
        """Handle user logout."""
        logout_user()
        ui.notify("You have been logged out", type="info")
        ui.navigate.to("/login")


class UserDashboard:
    """Dashboard for regular users."""

    def __init__(self, user: User):
        self.user = user
        self.navbar = DashboardNavbar(user)

    def create(self):
        """Create the user dashboard."""
        # Navigation
        self.navbar.create()

        # Main content
        with ui.column().classes("w-full p-6 bg-gray-50 min-h-screen"):
            # Welcome section
            with ui.card().classes("w-full p-6 mb-6 shadow-md bg-white rounded-xl"):
                ui.label("User Dashboard").classes("text-2xl font-bold text-gray-800 mb-4")
                ui.label(f"Hello, {self.user.full_name}! Welcome to your dashboard.").classes("text-gray-600 text-lg")

            # User info section
            with ui.card().classes("w-full p-6 mb-6 shadow-md bg-white rounded-xl"):
                ui.label("Your Information").classes("text-xl font-semibold text-gray-800 mb-4")

                with ui.row().classes("gap-8 w-full"):
                    with ui.column().classes("flex-1"):
                        self._create_info_item("Username", self.user.username)
                        self._create_info_item("Email", self.user.email)
                        self._create_info_item("Full Name", self.user.full_name)

                    with ui.column().classes("flex-1"):
                        self._create_info_item("Account Status", "Active" if self.user.is_active else "Inactive")
                        self._create_info_item("Verified", "Yes" if self.user.is_verified else "No")
                        roles_text = ", ".join([role.display_name for role in self.user.roles])
                        self._create_info_item("Roles", roles_text or "None")

            # Actions section
            with ui.card().classes("w-full p-6 shadow-md bg-white rounded-xl"):
                ui.label("Available Actions").classes("text-xl font-semibold text-gray-800 mb-4")

                with ui.row().classes("gap-4"):
                    ui.button(
                        "View Profile",
                        icon="person",
                        on_click=lambda: ui.notify("Profile feature coming soon!", type="info"),
                    ).classes("bg-blue-500 hover:bg-blue-600 text-white px-6 py-2")

                    ui.button(
                        "Settings",
                        icon="settings",
                        on_click=lambda: ui.notify("Settings feature coming soon!", type="info"),
                    ).classes("bg-gray-500 hover:bg-gray-600 text-white px-6 py-2")

    def _create_info_item(self, label: str, value: str):
        """Create an information item display."""
        with ui.column().classes("mb-3"):
            ui.label(label).classes("text-sm font-medium text-gray-500 uppercase tracking-wide")
            ui.label(value).classes("text-base text-gray-800 mt-1")


class AdminDashboard:
    """Dashboard for admin users."""

    def __init__(self, user: User):
        self.user = user
        self.navbar = DashboardNavbar(user)

    def create(self):
        """Create the admin dashboard."""
        # Navigation
        self.navbar.create()

        # Main content
        with ui.column().classes("w-full p-6 bg-gray-50 min-h-screen"):
            # Welcome section
            with ui.card().classes("w-full p-6 mb-6 shadow-md bg-white rounded-xl"):
                ui.label("Admin Dashboard").classes("text-2xl font-bold text-gray-800 mb-4")
                ui.label(f"Welcome, {self.user.full_name}! You have administrative access.").classes(
                    "text-gray-600 text-lg"
                )

            # Admin metrics
            with ui.row().classes("gap-4 w-full mb-6"):
                self._create_metric_card("Total Users", self._get_user_count(), "people")
                self._create_metric_card("Active Sessions", self._get_active_session_count(), "schedule")
                self._create_metric_card("Total Roles", self._get_role_count(), "security")

            # Admin actions
            with ui.card().classes("w-full p-6 shadow-md bg-white rounded-xl"):
                ui.label("Administrative Actions").classes("text-xl font-semibold text-gray-800 mb-4")

                with ui.row().classes("gap-4 flex-wrap"):
                    ui.button(
                        "Manage Users",
                        icon="people",
                        on_click=lambda: ui.notify("User management feature coming soon!", type="info"),
                    ).classes("bg-blue-500 hover:bg-blue-600 text-white px-6 py-2")

                    ui.button(
                        "Manage Roles",
                        icon="security",
                        on_click=lambda: ui.notify("Role management feature coming soon!", type="info"),
                    ).classes("bg-green-500 hover:bg-green-600 text-white px-6 py-2")

                    ui.button(
                        "View Sessions",
                        icon="schedule",
                        on_click=lambda: ui.notify("Session management feature coming soon!", type="info"),
                    ).classes("bg-purple-500 hover:bg-purple-600 text-white px-6 py-2")

                    ui.button(
                        "System Settings",
                        icon="settings",
                        on_click=lambda: ui.notify("System settings feature coming soon!", type="info"),
                    ).classes("bg-gray-500 hover:bg-gray-600 text-white px-6 py-2")

    def _create_metric_card(self, title: str, value: str, icon: str):
        """Create a metric card."""
        with ui.card().classes("p-6 bg-white shadow-lg rounded-xl hover:shadow-xl transition-shadow flex-1"):
            with ui.row().classes("items-center justify-between w-full"):
                with ui.column():
                    ui.label(title).classes("text-sm text-gray-500 uppercase tracking-wider")
                    ui.label(value).classes("text-3xl font-bold text-gray-800 mt-2")
                ui.icon(icon).classes("text-4xl text-blue-500")

    def _get_user_count(self) -> str:
        """Get total user count."""
        try:
            from sqlmodel import select
            from app.database import get_session
            from app.models import User

            with get_session() as session:
                statement = select(User)
                users = session.exec(statement).all()
                return str(len(users))
        except Exception as e:
            logger.error(f"Failed to get user count: {e}")
            return "N/A"

    def _get_active_session_count(self) -> str:
        """Get active session count."""
        try:
            from sqlmodel import select
            from app.database import get_session
            from app.models import UserSession
            from datetime import datetime

            with get_session() as session:
                statement = select(UserSession).where(
                    UserSession.is_active == True,  # noqa: E712
                    UserSession.expires_at > datetime.utcnow(),
                )
                sessions = session.exec(statement).all()
                return str(len(sessions))
        except Exception as e:
            logger.error(f"Failed to get active session count: {e}")
            return "N/A"

    def _get_role_count(self) -> str:
        """Get total role count."""
        try:
            from sqlmodel import select
            from app.database import get_session
            from app.models import Role

            with get_session() as session:
                statement = select(Role)
                roles = session.exec(statement).all()
                return str(len(roles))
        except Exception as e:
            logger.error(f"Failed to get role count: {e}")
            return "N/A"


def create():
    """Create dashboard page routes."""

    @ui.page("/dashboard")
    def user_dashboard_page():
        try:
            user = require_auth()
            dashboard = UserDashboard(user)
            dashboard.create()
        except AuthError:
            ui.navigate.to("/login")

    @ui.page("/admin/dashboard")
    def admin_dashboard_page():
        try:
            user = require_auth()
            if not is_admin(user):
                ui.notify("Admin access required", type="negative")
                ui.navigate.to("/dashboard")
                return

            dashboard = AdminDashboard(user)
            dashboard.create()
        except AuthError:
            ui.navigate.to("/login")
