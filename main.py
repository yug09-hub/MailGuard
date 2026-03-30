"""
Main entry point for Railway deployment.
This file imports the Flask app from app.py for gunicorn.
"""
from app import app

if __name__ == "__main__":
    app.run()
