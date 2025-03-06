# Web application

This is the web-application part of the project built in the python web framework Flask.


## Build process

-- `cd Inside Web-applicatio`/` if you're not already inside--

### Dependencies:
venv - Included in python3
pip - Included in python3

To start the virtual environment (Linux) - `source .venv/bin/activate`

pip install flask cryptography requests python-dotenv pytest 

-- `cd Inside Web-application`/` if you're not already inside--

To initiate the database - `flask --app flask_app init-db`

The app is run from Web-application/ in debug mode with  - `flask --app flask_app run --debug`

## Leaving the virtual environment
-- `deactivate`