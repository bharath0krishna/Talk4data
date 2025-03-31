import os

class Config:
    SECRET_KEY = os.urandom(24)  # Change this to a fixed secret key for production
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
