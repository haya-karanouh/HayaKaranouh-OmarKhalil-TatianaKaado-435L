"""Business logic for reports service."""


class ReportsService:
    def health(self):
        return {"service": "reports", "status": "healthy"}
