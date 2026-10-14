"""Business logic for incidents service."""


class IncidentsService:
    def health(self):
        return {"service": "incidents", "status": "healthy"}
