"""Isolated demonstration: intentionally vulnerable API and corrected API."""
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer

# These are synthetic fixtures, not real credentials or a production auth provider.
TOKEN_USERS = {"demo-a": "A", "demo-b": "B"}
ORDERS = {
    101: {"id": 101, "owner_id": "A", "item": "Notebook"},
    202: {"id": 202, "owner_id": "B", "item": "Headphones"},
}
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def current_user(token: str = Depends(oauth2_scheme)) -> str:
    user = TOKEN_USERS.get(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid demo token")
    return user


def make_app(*, vulnerable: bool = False) -> FastAPI:
    app = FastAPI()

    @app.get("/orders/{order_id}")
    def get_order(order_id: int, request: Request, user: str = Depends(current_user)) -> dict:
        if vulnerable and (request.client is None or request.client.host != "testclient"):
            raise HTTPException(status_code=403, detail="Vulnerable demo is in-process only")
        order = ORDERS.get(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="Order not found")
        if not vulnerable and order["owner_id"] != user:
            raise HTTPException(status_code=404, detail="Order not found")
        return order

    return app
