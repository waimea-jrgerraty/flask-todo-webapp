#===========================================================
# Error Related Functions
#===========================================================

from flask import render_template
import traceback
import sys


#-----------------------------------------------------------
# 500 Server error page
#-----------------------------------------------------------
def server_error(message):
    return render_template("pages/500.jinja", error=message), 500


#-----------------------------------------------------------
# 404 Page not found error page
#-----------------------------------------------------------
def not_found_error():
    return render_template("pages/404.jinja"), 404


#-----------------------------------------------------------
# Provide error handlers to the Flask app
#-----------------------------------------------------------
def register_error_handlers(app):

    #------------------------------
    # 404 Page not found error page
    #------------------------------
    @app.errorhandler(404)
    def show_not_found(e):
        return not_found_error()


    #------------------------------
    # 500 Server error page
    #------------------------------
    @app.errorhandler(500)
    def show_server_error(e):
        return server_error(str(e))


    #------------------------------
    # General exception error page
    #------------------------------
    @app.errorhandler(Exception)
    def handle_exception(e):
        # Only show verbose error details if debugging
        if app.debug:
            # Get the last frame from the traceback code (not Flask internals)
            tb = traceback.extract_tb(sys.exc_info()[2])

            # Find the last frame that's in your the directory
            app_frame = None
            for frame in reversed(tb):
                if 'venv' not in frame.filename and 'site-packages' not in frame.filename:
                    app_frame = frame
                    break

            error_msg = f"""
                <table class="error">
                    <tr><th>Error</th><td>{type(e).__name__}</td></tr>
                    <tr><th>Details</th><td>{str(e)}</td></tr>
            """

            # Do we have a matching error frame?
            if app_frame:
                filename = app_frame.filename.replace(app.root_path, "")
                error_msg += f"""
                    <tr><th>Code</th><td>{app_frame.line}</td></tr>
                    <tr><th>File</th><td>{filename}</td></tr>
                    <tr><th>Line</th><td>{app_frame.lineno}</td></tr>
                """

            error_msg += "</table>"

            print(app.root_path)

            return server_error(error_msg)

        # Else just a generic message
        return server_error("An unexpected server error occurred")
