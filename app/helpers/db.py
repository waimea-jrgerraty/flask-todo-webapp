#===========================================================
# Database Related Functions
#===========================================================

from libsql_client import create_client_sync, LibsqlError
from contextlib import contextmanager
from dotenv import load_dotenv
from os import getenv, path


# Load Turso environment variables from the .env file
load_dotenv()
TURSO_URL = getenv("TURSO_URL")
TURSO_KEY = getenv("TURSO_KEY")

# Define the locations of our DB files
DB_FOLDER   = path.join(path.dirname(__file__), "db")
SCHEMA_FILE = path.join(DB_FOLDER, "schema.sql")


#-----------------------------------------------------------
# Connect to the Turso DB and return the connection
#-----------------------------------------------------------
@contextmanager
def connect_db():
    client = None

    try:
        # Attempt to connect Turso DB, and pass back the connection
        client = create_client_sync(url=TURSO_URL, auth_token=TURSO_KEY)
        yield client

    finally:
        # Properly close the connection when done
        if client is not None:
            client.close()

