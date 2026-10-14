"""Business logic for logs service."""


class LogsService:
    def health(self):
        return {"service": "logs", "status": "healthy"}
