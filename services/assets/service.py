"""Business logic for assets service."""


class AssetsService:
    def health(self):
        return {"service": "assets", "status": "healthy"}
