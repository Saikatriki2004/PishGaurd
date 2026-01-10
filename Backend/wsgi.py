"""
WSGI Entry Point for Production Deployment

This module serves as the entry point for WSGI servers like Gunicorn or uWSGI.

Usage with Gunicorn:
    gunicorn wsgi:app --bind 0.0.0.0:5000 --workers 4

Usage with uWSGI:
    uwsgi --http 0.0.0.0:5000 --wsgi-file wsgi.py --callable app --processes 4

SECURITY NOTES:
    - This entry point does NOT enable debug mode
    - The Werkzeug debugger is NOT available through this entry point
    - For development, use: python app.py with FLASK_DEBUG=true
"""

from app import app

if __name__ == "__main__":
    # This block only runs if wsgi.py is executed directly (for testing)
    # In production, Gunicorn/uWSGI imports the 'app' object directly
    app.run()
