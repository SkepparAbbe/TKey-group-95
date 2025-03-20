import sqlite3

import click

# G is a special object that is unique for each request
# It is used to store data that might be accessed by mulitple functions during the request
# The connection is stored and reused instead of creating a new connection each time.
from flask import current_app, g
import psycopg2
import os
from urllib.parse import urlparse

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


# Deprecated, migrating to postgresql hosted on Supabase
def get_db():
    """Uses the current_app since this is run when the application factory has done its magic.\n
       Gets the DATABASE variable descibing where the database is located. \n
       Sets the db object in g"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # Makes queries return python dicts {key: val} = {primary_key: [val1, val2]} (I think)
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(e=None):
    #Releases db from g object.
    db = g.pop('db', None)

    if db is not None:
        db.close()



def init_db():
    """Runs schema.sql, currently nuking the database and setting the tables."""
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


# Creates a flask command for initialising the database
@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

 
def init_app(app):
    """Registers the close_db and init_db_command with the application.\n
        Should be called from __init__.py"""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)


