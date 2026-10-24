"""Two in-memory order APIs for an isolated object-authorization exercise."""

from typing import Annotated, TypedDict

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer


class Order(TypedDict):
    id: int
    owner_id: str
    item: str


# Synthetic identities and orders: this is not a production authentication scheme.
TOKEN_USERS = {"demo-a": "A", "demo-b": "B"}
ORDERS: dict[int, Order] = {
    101: {"id": 101, "owner_id": "A", "item": "Notebook"},
    202: {"id": 202, "owner_id": "B", "item": "Headphones"},
}
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    user = TOKEN_USERS.get(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid demo token")
    return user


def make_app(*, vulnerable: bool = False) -> FastAPI:
    """Create a fixed API by default; expose the vulnerable path only to TestClient."""
    app = FastAPI()

    @app.get("/orders/{order_id}")
    def get_order(
        order_id: int,
        request: Request,
        user: Annotated[str, Depends(current_user)],
    ) -> Order:
        if vulnerable and (request.client is None or request.client.host != "testclient"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Vulnerable demo is in-process only",
            )

        order = ORDERS.get(order_id)
        if order is None or (not vulnerable and order["owner_id"] != user):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
        return order

    return app
