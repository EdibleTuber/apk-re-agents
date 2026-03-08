import uvicorn

from apk_re.config import Settings
from apk_re.coordinator.api import create_app


def main():
    settings = Settings()
    app = create_app(shared_volume=str(settings.shared_volume))
    uvicorn.run(app, host="0.0.0.0", port=settings.coordinator_port)


if __name__ == "__main__":
    main()
