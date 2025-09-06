from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from typing import Optional
from starlette.status import HTTP_401_UNAUTHORIZED
from starlette.requests import Request
import secrets

app = FastAPI(title="Demo API with All Auth Methods", docs_url="/docs", openapi_url="/openapi.json")

# Credentials
USERNAME = "testapi"
PASSWORD = "testapi"
API_KEY = "testapi"
BEARER_TOKEN = "testapi"

# Auth Schemes
basic_auth = HTTPBasic()
bearer_auth = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_basic(credentials: HTTPBasicCredentials = Depends(basic_auth)):
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def verify_bearer(credentials: HTTPAuthorizationCredentials = Depends(bearer_auth)):
    if not secrets.compare_digest(credentials.credentials, BEARER_TOKEN):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials

def verify_api_key(api_key: Optional[str] = Security(api_key_header)):
    if not api_key or not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key

# CRUD Endpoints
@app.get("/items", summary="Get items", tags=["CRUD"], response_description="List of items")
def get_items(auth: str = Depends(verify_basic)):
    return [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]

@app.post("/items", summary="Create item", tags=["CRUD"], response_description="Created item")
def create_item(item: dict, auth: str = Depends(verify_bearer)):
    return {"id": 3, **item}

@app.put("/items/{item_id}", summary="Update item", tags=["CRUD"], response_description="Updated item")
def update_item(item_id: int, item: dict, api_key: str = Depends(verify_api_key)):
    return {"id": item_id, **item}

@app.delete("/items/{item_id}", summary="Delete item", tags=["CRUD"], response_description="Delete result")
def delete_item(item_id: int, auth: str = Depends(verify_basic)):
    return {"result": f"Item {item_id} deleted"}

# Custom OpenAPI to show all auth methods
@app.get("/openapi.json", include_in_schema=False)
def custom_openapi():
    return JSONResponse(get_openapi(
        title=app.title,
        version="1.0.0",
        routes=app.routes,
        description="API supporting GET, POST, PUT, DELETE with Basic, Bearer, and API Key authentication.\n\nCredentials: username=testapi, password=testapi, API Key/Bearer Token=testapi."
    ))

# Root
@app.get("/", include_in_schema=False)
def root():
    return {"message": "API is running. See /docs for Swagger UI."}
