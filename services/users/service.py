"""Business logic for users service."""


class UsersService:
    def health(self):
        return {"service": "users", "status": "healthy"}
