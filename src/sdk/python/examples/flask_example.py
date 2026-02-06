"""
Zalt Auth Python SDK - Flask Integration Example

This example demonstrates how to integrate Zalt Auth with Flask.

Run with: flask run
"""

# Note: Requires flask to be installed
# pip install zalt-auth[flask]

try:
    from flask import Flask, jsonify, request
    from zalt_auth.integrations.flask import (
        ZaltFlask,
        login_required,
        permission_required,
        current_user,
        is_authenticated,
    )
    
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "your-secret-key"
    
    # Initialize Zalt
    zalt = ZaltFlask(
        app,
        publishable_key="pk_test_12345678901234567890123456789012",
        realm_id="example-realm",
        debug=True,
    )
    
    
    @app.route("/")
    def root():
        """Public endpoint."""
        return jsonify({"message": "Welcome to Zalt Auth Flask Example"})
    
    
    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({"status": "healthy"})
    
    
    @app.route("/me")
    @login_required
    def get_me():
        """
        Get current user profile.
        
        Requires: Bearer token in Authorization header
        """
        return jsonify({
            "id": current_user.id,
            "email": current_user.email,
            "profile": {
                "first_name": current_user.profile.first_name,
                "last_name": current_user.profile.last_name,
            },
            "mfa_enabled": current_user.mfa_enabled,
        })
    
    
    @app.route("/profile")
    def get_profile():
        """
        Get user profile (optional auth).
        
        Returns user info if authenticated, guest message otherwise.
        """
        if is_authenticated():
            return jsonify({
                "authenticated": True,
                "message": f"Hello, {current_user.email}!",
            })
        return jsonify({
            "authenticated": False,
            "message": "Hello, guest!",
        })
    
    
    @app.route("/admin")
    @permission_required(["admin:read"])
    def admin_only():
        """
        Admin-only endpoint.
        
        Requires: admin:read permission
        """
        return jsonify({
            "admin": True,
            "user_id": current_user.id,
            "message": "Welcome, admin!",
        })
    
    
    @app.route("/users")
    @permission_required(["users:read"])
    def list_users():
        """
        List users endpoint.
        
        Requires: users:read permission
        """
        return jsonify({
            "users": [],  # Would fetch from database
            "requested_by": current_user.id,
        })
    
    
    if __name__ == "__main__":
        app.run(debug=True, port=5000)

except ImportError as e:
    print(f"Flask not installed. Install with: pip install zalt-auth[flask]")
    print(f"Error: {e}")
