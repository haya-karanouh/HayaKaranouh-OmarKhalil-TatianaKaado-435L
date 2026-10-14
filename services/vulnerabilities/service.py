"""Business logic for vulnerabilities service."""


class VulnerabilitiesService:
    def health(self):
        return {"service": "vulnerabilities", "status": "healthy"}
