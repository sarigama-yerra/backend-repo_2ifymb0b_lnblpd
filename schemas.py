"""
Database Schemas for E‑commerce App

Each Pydantic model corresponds to a MongoDB collection. The collection name is the lowercase of the class name.

Example: class User -> collection "user"
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Core domain models

class Address(BaseModel):
    full_name: str
    line1: str
    line2: Optional[str] = None
    city: str
    state: Optional[str] = None
    postal_code: str
    country: str
    phone: Optional[str] = None

class User(BaseModel):
    name: str
    email: EmailStr
    hashed_password: str
    is_active: bool = True
    is_admin: bool = False
    default_address: Optional[Address] = None
    addresses: List[Address] = Field(default_factory=list)

class Category(BaseModel):
    name: str
    slug: str
    parent_id: Optional[str] = None
    description: Optional[str] = None

class Product(BaseModel):
    title: str
    slug: str
    description: Optional[str] = None
    brand: Optional[str] = None
    price: float = Field(..., ge=0)
    images: List[str] = Field(default_factory=list)
    category_ids: List[str] = Field(default_factory=list)
    specs: Dict[str, Any] = Field(default_factory=dict)
    inventory: int = Field(0, ge=0)
    rating: float = Field(0, ge=0, le=5)
    rating_count: int = 0
    is_active: bool = True

class Review(BaseModel):
    product_id: str
    user_id: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None

class CartItem(BaseModel):
    product_id: str
    quantity: int = Field(1, ge=1)
    price_at_add: float = Field(..., ge=0)

class Cart(BaseModel):
    user_id: str
    items: List[CartItem] = Field(default_factory=list)
    saved_for_later: List[CartItem] = Field(default_factory=list)

class OrderItem(BaseModel):
    product_id: str
    title: str
    image: Optional[str] = None
    quantity: int = Field(1, ge=1)
    unit_price: float = Field(..., ge=0)
    subtotal: float = Field(..., ge=0)

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    shipping_address: Address
    subtotal: float
    tax: float
    shipping: float
    total: float
    currency: str = "USD"
    status: str = Field("pending", description="pending|paid|failed|shipped|delivered|cancelled")
    payment_provider: Optional[str] = None
    payment_ref: Optional[str] = None
    placed_at: datetime = Field(default_factory=datetime.utcnow)

class Coupon(BaseModel):
    code: str
    description: Optional[str] = None
    discount_type: str = Field("percent", description="percent|fixed")
    value: float = Field(..., ge=0)
    active: bool = True
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
