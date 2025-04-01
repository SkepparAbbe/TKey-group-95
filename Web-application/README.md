# Web application

This is the web-application part of the project built in the python web framework Flask.


## Build process

### Data
You need to provide an postgresql database following schema.sql. Do this by creating a .env file in the root directory. Insert your database URL as SUPABASE_DATABASE_URL=[URL]

### local development

-- `cd Inside Web-application`/` if you're not already inside--

### Dependencies:
venv - Included in python3
pip - Included in python3

To start the virtual environment (Linux) - `source .venv/bin/activate`

pip install flask cryptography requests python-dotenv pytest psychopg2-binary 

-- `cd Inside Web-application`/` if you're not already inside--

The app is run from Web-application/ in debug mode with  - `flask --app flask_app run --debug`

## Leaving the virtual environment
-- `deactivate`

## Run production

### Dependencies:
venv - Included in python3
pip - Included in python3

To start the virtual environment (Linux) - `source .venv/bin/activate`

`pip install flask cryptography requests python-dotenv pytest psycopg2-binary gunicorn`

### Run the server in production with Gunicorn
`cd Web-application`
`gunicorn 'flask_app:create_app()'`
