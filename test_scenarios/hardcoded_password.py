class AuthenticationService:
    def __init__(self):
        # This is a hardcoded password
        self.admin_password = "super_secret_admin_pwd_123!"
        self.api_key = "1234567890abcdef"

    def login(self, username, password):
        if username == "admin" and password == self.admin_password:
            return True
        return False
