#===========================================================
# Auth Related Functions
#===========================================================

from flask import redirect, session
from functools import wraps


#-----------------------------------------------------------
# A decorator function to check user logged in
#-----------------------------------------------------------
def login_required(func):
    @wraps(func)
    # Wrap a given function...
    def wrapper(*args, **kwargs):

        # Is the user logged in?
        if 'user_id' in session:
            # Yes, so run function
            return func(*args, **kwargs)

        # No, so go to home page
        return redirect("/")

    return wrapper


