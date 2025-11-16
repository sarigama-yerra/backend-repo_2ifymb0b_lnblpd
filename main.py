import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# App setup
app = FastAPI(title="E-commerce API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security/JWT setup
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))
security = HTTPBearer()
password_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Utilities
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return v
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


def oid_str(oid):
    try:
        return str(oid)
    except Exception:
        return oid


def hash_password(password: str) -> str:
    return password_ctx.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_ctx.verify(password, hashed)


def create_token(user: dict) -> str:
    payload = {
        "sub": str(user["_id"]),
        "email": user.get("email"),
        "is_admin": user.get("is_admin", False),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    uid = payload.get("sub")
    user = db["user"].find_one({"_id": ObjectId(uid)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# Schemas (request/response)
class Address(BaseModel):
    full_name: str
    line1: str
    line2: Optional[str] = None
    city: str
    state: Optional[str] = None
    postal_code: str
    country: str
    phone: Optional[str] = None


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProductIn(BaseModel):
    title: str
    slug: str
    price: float
    description: Optional[str] = None
    brand: Optional[str] = None
    images: List[str] = []
    category_ids: List[str] = []
    specs: Dict[str, Any] = {}
    inventory: int = 0
    is_active: bool = True


class ProductOut(ProductIn):
    id: str
    rating: float = 0
    rating_count: int = 0


class CartItemIn(BaseModel):
    product_id: str
    quantity: int = 1


class CheckoutRequest(BaseModel):
    shipping_address: Address
    payment_method: str = "card"
    coupon_code: Optional[str] = None


# Health and helpers
@app.get("/")
def root():
    return {"message": "E-commerce API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
    return response


# Auth
@app.post("/auth/register")
def register(payload: RegisterRequest):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": payload.name,
        "email": payload.email,
        "hashed_password": hash_password(payload.password),
        "is_active": True,
        "is_admin": False,
        "addresses": [],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    inserted_id = db["user"].insert_one(doc).inserted_id
    user = db["user"].find_one({"_id": inserted_id})
    token = create_token(user)
    return {"token": token, "user": {"id": str(inserted_id), "name": user["name"], "email": user["email"], "is_admin": user.get("is_admin", False)}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "is_admin": user.get("is_admin", False)}}


@app.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": str(current_user["_id"]),
        "name": current_user.get("name"),
        "email": current_user.get("email"),
        "is_admin": current_user.get("is_admin", False),
        "addresses": current_user.get("addresses", []),
    }


@app.put("/me")
async def update_profile(update: Dict[str, Any] = Body(...), current_user: dict = Depends(get_current_user)):
    allowed = {"name", "addresses"}
    update = {k: v for k, v in update.items() if k in allowed}
    update["updated_at"] = datetime.utcnow()
    db["user"].update_one({"_id": current_user["_id"]}, {"$set": update})
    user = db["user"].find_one({"_id": current_user["_id"]})
    return {
        "id": str(user["_id"]),
        "name": user.get("name"),
        "email": user.get("email"),
        "is_admin": user.get("is_admin", False),
        "addresses": user.get("addresses", []),
    }


# Products
@app.get("/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, brand: Optional[str] = None,
                  sort: Optional[str] = None, page: int = 1, page_size: int = 12, min_price: Optional[float] = None,
                  max_price: Optional[float] = None):
    filt: Dict[str, Any] = {"is_active": True}
    if q:
        filt["title"] = {"$regex": q, "$options": "i"}
    if category:
        filt["category_ids"] = category
    if brand:
        filt["brand"] = brand
    price_cond = {}
    if min_price is not None:
        price_cond["$gte"] = min_price
    if max_price is not None:
        price_cond["$lte"] = max_price
    if price_cond:
        filt["price"] = price_cond

    cursor = db["product"].find(filt)
    if sort == "price_asc":
        cursor = cursor.sort("price", 1)
    elif sort == "price_desc":
        cursor = cursor.sort("price", -1)
    elif sort == "newest":
        cursor = cursor.sort("created_at", -1)
    elif sort == "rating":
        cursor = cursor.sort("rating", -1)

    total = cursor.count() if hasattr(cursor, 'count') else db["product"].count_documents(filt)
    cursor = cursor.skip((page - 1) * page_size).limit(page_size)

    items = []
    for p in cursor:
        p["id"] = str(p.pop("_id"))
        items.append(p)
    return {"items": items, "page": page, "page_size": page_size, "total": total}


@app.get("/products/{slug}")
def get_product(slug: str):
    p = db["product"].find_one({"slug": slug})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    p["id"] = str(p.pop("_id"))
    return p


@app.post("/products")
async def create_product(payload: ProductIn, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    doc = payload.model_dump()
    doc.update({"rating": 0.0, "rating_count": 0, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    inserted = db["product"].insert_one(doc).inserted_id
    return {"id": str(inserted)}


@app.put("/products/{product_id}")
async def update_product(product_id: str, payload: Dict[str, Any] = Body(...), user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    payload["updated_at"] = datetime.utcnow()
    db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": payload})
    return {"id": product_id, "updated": True}


@app.delete("/products/{product_id}")
async def delete_product(product_id: str, user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    db["product"].delete_one({"_id": ObjectId(product_id)})
    return {"id": product_id, "deleted": True}


# Cart
@app.get("/cart")
async def get_cart(user: dict = Depends(get_current_user)):
    cart = db["cart"].find_one({"user_id": str(user["_id"])})
    if not cart:
        cart = {"user_id": str(user["_id"]), "items": [], "saved_for_later": []}
        db["cart"].insert_one(cart)
    cart["id"] = str(cart.pop("_id")) if cart.get("_id") else None
    return cart


@app.post("/cart/add")
async def cart_add(item: CartItemIn, user: dict = Depends(get_current_user)):
    uid = str(user["_id"])
    cart = db["cart"].find_one({"user_id": uid})
    if not cart:
        cart = {"user_id": uid, "items": [], "saved_for_later": []}
        db["cart"].insert_one(cart)
    # Ensure product exists and get current price/title
    product = db["product"].find_one({"_id": ObjectId(item.product_id)})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    items = cart.get("items", [])
    found = False
    for it in items:
        if it["product_id"] == item.product_id:
            it["quantity"] += item.quantity
            found = True
            break
    if not found:
        items.append({
            "product_id": item.product_id,
            "quantity": item.quantity,
            "price_at_add": product.get("price", 0.0),
            "title": product.get("title"),
            "image": (product.get("images") or [None])[0]
        })
    db["cart"].update_one({"user_id": uid}, {"$set": {"items": items}})
    return await get_cart(user)


@app.post("/cart/update")
async def cart_update(item: CartItemIn, user: dict = Depends(get_current_user)):
    uid = str(user["_id"])
    cart = db["cart"].find_one({"user_id": uid})
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    items = cart.get("items", [])
    for it in items:
        if it["product_id"] == item.product_id:
            it["quantity"] = max(1, item.quantity)
            break
    db["cart"].update_one({"user_id": uid}, {"$set": {"items": items}})
    return await get_cart(user)


@app.post("/cart/remove")
async def cart_remove(item: CartItemIn, user: dict = Depends(get_current_user)):
    uid = str(user["_id"])
    cart = db["cart"].find_one({"user_id": uid})
    items = [it for it in cart.get("items", []) if it["product_id"] != item.product_id]
    db["cart"].update_one({"user_id": uid}, {"$set": {"items": items}})
    return await get_cart(user)


# Checkout & Orders
@app.post("/checkout")
async def checkout(payload: CheckoutRequest, user: dict = Depends(get_current_user)):
    uid = str(user["_id"]) 
    cart = db["cart"].find_one({"user_id": uid})
    if not cart or not cart.get("items"):
        raise HTTPException(status_code=400, detail="Cart is empty")

    # Calculate totals based on current product prices to ensure up-to-date total
    items = []
    subtotal = 0.0
    for it in cart.get("items", []):
        prod = db["product"].find_one({"_id": ObjectId(it["product_id"])})
        if not prod:
            continue
        qty = it["quantity"]
        price = float(prod.get("price", it.get("price_at_add", 0.0)))
        subtotal += price * qty
        items.append({
            "product_id": it["product_id"],
            "title": prod.get("title"),
            "image": (prod.get("images") or [None])[0],
            "quantity": qty,
            "unit_price": price,
            "subtotal": round(price * qty, 2),
        })
    tax_rate = 0.1  # 10% demo tax
    tax = round(subtotal * tax_rate, 2)
    shipping = 0.0 if subtotal >= 50 else 5.0
    total = round(subtotal + tax + shipping, 2)

    # Simulate payment success (integrate Stripe/PayPal in production)
    payment_ref = f"SIM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    order_doc = {
        "user_id": uid,
        "items": items,
        "shipping_address": payload.shipping_address.model_dump(),
        "subtotal": round(subtotal, 2),
        "tax": tax,
        "shipping": shipping,
        "total": total,
        "currency": "USD",
        "status": "paid",
        "payment_provider": payload.payment_method,
        "payment_ref": payment_ref,
        "placed_at": datetime.utcnow(),
    }
    order_id = db["order"].insert_one(order_doc).inserted_id

    # Decrement inventory
    for it in items:
        try:
            db["product"].update_one({"_id": ObjectId(it["product_id"])}, {"$inc": {"inventory": -it["quantity"]}})
        except Exception:
            pass

    # Clear cart
    db["cart"].update_one({"user_id": uid}, {"$set": {"items": []}})

    return {"order_id": str(order_id), "status": "paid", "total": total}


@app.get("/orders")
async def list_orders(user: dict = Depends(get_current_user)):
    uid = str(user["_id"])
    cursor = db["order"].find({"user_id": uid}).sort("placed_at", -1)
    items = []
    for o in cursor:
        o["id"] = str(o.pop("_id"))
        items.append(o)
    return {"items": items}


# Optional: seed sample products for demo
@app.post("/admin/seed")
async def seed_products(user: dict = Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    if db["product"].count_documents({}) > 0:
        return {"seeded": False, "message": "Products already exist"}
    samples = [
        {
            "title": "Minimalist Card Holder",
            "slug": "minimalist-card-holder",
            "price": 19.99,
            "description": "Slim wallet for cards.",
            "brand": "NeoWallet",
            "images": ["https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77?q=80&w=1200&auto=format&fit=crop"],
            "category_ids": ["accessories"],
            "inventory": 100,
            "rating": 4.5,
            "rating_count": 48,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        },
        {
            "title": "Pastel Visa Gift Card",
            "slug": "pastel-visa-gift-card",
            "price": 50.0,
            "description": "A stylish prepaid card for any occasion.",
            "brand": "Visa",
            "images": ["https://images.unsplash.com/photo-1563013544-824ae1b704d3?q=80&w=1200&auto=format&fit=crop"],
            "category_ids": ["gift-cards"],
            "inventory": 500,
            "rating": 4.8,
            "rating_count": 132,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        },
        {
            "title": "Modern Phone Stand",
            "slug": "modern-phone-stand",
            "price": 29.0,
            "description": "Aluminum phone stand with cable management.",
            "brand": "DeskMate",
            "images": ["https://images.unsplash.com/photo-1518770660439-4636190af475?q=80&w=1200&auto=format&fit=crop"],
            "category_ids": ["desk"],
            "inventory": 200,
            "rating": 4.3,
            "rating_count": 76,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
    ]
    db["product"].insert_many(samples)
    return {"seeded": True, "count": len(samples)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
