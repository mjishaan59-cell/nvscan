from functools import wraps

from flask import redirect, session, url_for
from werkzeug.security import check_password_hash


def authenticate_user(database, username, password):
    """Authenticate a user using a securely stored password hash."""

    user = database.get_user_by_username(username)

    if user is None:
        return None

    if not user.get("is_active"):
        return None

    if not check_password_hash(
        user["password_hash"],
        password,
    ):
        return None

    return user


def login_user(user):
    """Store the authenticated user in the Flask session."""

    session.clear()

    session["user_id"] = user["id"]
    session["username"] = user["username"]


def logout_user():
    """Clear the current authenticated session."""

    session.clear()


def current_user(database):
    """Return the currently authenticated user."""

    user_id = session.get("user_id")

    if user_id is None:
        return None

    user = database.get_user(user_id)

    if user is None:
        session.clear()
        return None

    if not user.get("is_active"):
        session.clear()
        return None

    return user


def login_required(view_function):
    """Require an authenticated user before accessing a route."""

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs,
        )

    return wrapped_view
