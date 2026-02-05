from fastapi import FastAPI, Form, HTTPException


app = FastAPI(title="Vulnerable Backend")


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "password":
        return {"message": "welcome"}
    raise HTTPException(status_code=401, detail="invalid credentials")


@app.get("/search")
async def search(q: str = ""):
    return {"results": f"searched for {q}"}


@app.get("/admin")
async def admin():
    raise HTTPException(status_code=403, detail="forbidden")

