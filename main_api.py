import os
from datetime import timedelta

import requests as r
from fastapi import FastAPI, HTTPException
from fastapi.params import Cookie
from firebase_admin import auth, credentials, initialize_app
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

SECRETS = {
    "FIREBASE_KEY": os.environ.get("FIREBASE_KEY"),
    "ORIGINS": os.environ.get("ORIGINS"),
}

app = FastAPI()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=SECRETS["ORIGINS"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cred = credentials.Certificate("./firebase-key.json")
initialize_app(cred)


class Auth(BaseModel):
    username: str
    password: str


def get_id_token(custom_token):
    API_KEY = SECRETS["FIREBASE_KEY"]
    res = r.post(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={API_KEY}",
        data={"token": custom_token, "returnSecureToken": True},
    ).json()

    return res


@app.post("/register")
async def register(input: Auth):
    try:
        user = auth.create_user(uid=input.username, password=input.password)
    except auth.UidAlreadyExistsError:
        raise HTTPException(409)

    return user


@app.post("/login")
async def login(input: Auth, response: Response):
    try:
        user = auth.get_user(input.username)
    except auth.UserNotFoundError:
        raise HTTPException(404)

    custom_token = auth.create_custom_token(user.uid)
    id_token = get_id_token(custom_token)

    session_cookie = auth.create_session_cookie(
        id_token["idToken"], timedelta(days=1)
    )

    response.set_cookie(
        key="session", value=session_cookie, httponly=True, samesite="lax"
    )

    return auth.verify_id_token(id_token["idToken"])


@app.post("/logout")
async def logout(response: Response, session: str = Cookie(None)):
    if session is None:
        raise HTTPException(404, "cookie not found")

    try:
        verification = auth.verify_session_cookie(session)
        auth.revoke_refresh_tokens(verification["sub"])
    except auth.InvalidSessionCookieError:
        raise HTTPException(401)

    response.delete_cookie("session")

    return True
