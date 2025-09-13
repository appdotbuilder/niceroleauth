from app.database import create_tables
from app.services.user_service import create_default_users_and_roles
import app.pages.login
import app.pages.dashboard


def startup() -> None:
    # this function is called before the first request
    create_tables()
    create_default_users_and_roles()
    app.pages.login.create()
    app.pages.dashboard.create()
