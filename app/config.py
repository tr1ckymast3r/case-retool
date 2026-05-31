import os


class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/retool.db")
    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
    REPORTS_DIR = os.getenv("REPORTS_DIR", "/app/reports")
    WORKER_DATA_DIR = os.getenv("WORKER_DATA_DIR", "/data")

    @property
    def WORKER_INPUT(self):
        return os.path.join(self.WORKER_DATA_DIR, "input")

    @property
    def WORKER_OUTPUT(self):
        return os.path.join(self.WORKER_DATA_DIR, "output")


settings = Settings()
