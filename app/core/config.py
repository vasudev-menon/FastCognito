from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    AWS_REGION_NAME: str
    AWS_COGNITO_APP_CLIENT_ID: str
    AWS_COGNITO_USER_POOL_ID: str
    CLIENT_SECRET: str

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()


# Cache settings to improve performance
@lru_cache
def get_settings():
    return settings


env_vars = get_settings()
