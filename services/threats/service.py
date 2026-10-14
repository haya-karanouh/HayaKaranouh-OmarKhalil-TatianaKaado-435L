"""Business logic for threats service."""


class ThreatsService:
    def health(self):
        return {"service": "threats", "status": "healthy"}
