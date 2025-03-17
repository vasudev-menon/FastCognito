from fastapi import FastAPI

from app.routes.auth_route import auth_router


app = FastAPI(
    title="FastCognito",
    description="FastAPI Cognito API authentication service",
    version="1.0.0",
)


# Index health check
@app.get("/")
def index():
    return {"message": "Authentication service"}


app.include_router(auth_router)
