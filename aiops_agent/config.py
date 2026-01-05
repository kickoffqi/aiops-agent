from pydantic import BaseModel, Field
import os


class Settings(BaseModel):
    prometheus_url: str = Field(default="http://localhost:9090")
    loki_url: str = Field(default="http://localhost:3100")
    app_label: str = Field(default="flask-demo")
    namespace: str = Field(default="default")
    lookback_minutes: int = Field(default=15)

    bearer_token: str | None = Field(default=None)
    basic_user: str | None = Field(default=None)
    basic_pass: str | None = Field(default=None)


def load_settings() -> Settings:
    """
    Load settings from environment variables with sane defaults.
    """
    return Settings(
        prometheus_url=os.getenv("PROM_URL", "http://localhost:9090"),
        loki_url=os.getenv("LOKI_URL", "http://localhost:3100"),
        app_label=os.getenv("APP_LABEL", "flask-demo"),
        namespace=os.getenv("NAMESPACE", "default"),
        lookback_minutes=int(os.getenv("LOOKBACK_MIN", "15")),
        bearer_token=os.getenv("BEARER_TOKEN"),
        basic_user=os.getenv("BASIC_USER"),
        basic_pass=os.getenv("BASIC_PASS"),
    )