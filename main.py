import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from passlib.context import CryptContext
from bson.objectid import ObjectId

from database import db, create_document

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisterRequest(BaseModel):
    name: str = Field(...)
    email: EmailStr
    password: str = Field(..., min_length=6)
    phone: Optional[str] = None
    city: Optional[str] = None
    blood_group: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.get("/")
def read_root():
    return {"message": "Blood Bank API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    return response


@app.post("/auth/register")
def register_user(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = db["blooduser"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(payload.password)
    document = {
        "name": payload.name,
        "email": payload.email.lower(),
        "phone": payload.phone,
        "city": payload.city,
        "blood_group": payload.blood_group,
        "role": "user",
        "password_hash": password_hash,
        "is_active": True,
    }

    inserted_id = create_document("blooduser", document)

    return {
        "status": "success",
        "message": "Registration successful",
        "user": {
            "id": inserted_id,
            "name": document["name"],
            "email": document["email"],
            "city": document["city"],
            "blood_group": document["blood_group"],
        },
    }


@app.post("/auth/login")
def login_user(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["blooduser"].find_one({"email": payload.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is inactive")

    return {
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": str(user.get("_id")),
            "name": user.get("name"),
            "email": user.get("email"),
            "city": user.get("city"),
            "blood_group": user.get("blood_group"),
        },
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
