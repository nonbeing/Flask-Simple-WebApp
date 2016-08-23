#!flask/bin/python
from app import app
DEBUG_MODE=False

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=DEBUG_MODE)
