"""Business logic for notifications service."""


class NotificationsService:
    def health(self):
        return {"service": "notifications", "status": "healthy"}
