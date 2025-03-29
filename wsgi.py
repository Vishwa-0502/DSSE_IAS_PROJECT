import os
from app import app
from routes import register_routes

# Register all routes
register_routes(app)

# For Vercel serverless deployment
app.debug = os.environ.get('DEBUG', 'False').lower() == 'true'

if __name__ == "__main__":
    # For local development
    app.run(host="0.0.0.0", port=5000, debug=True)
