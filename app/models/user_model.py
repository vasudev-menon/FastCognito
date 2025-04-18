from enum import Enum
from typing import Annotated, Optional

from annotated_types import MaxLen, MinLen
from pydantic import BaseModel, EmailStr, Field


class Challenge(str, Enum):
    # PASSWORD_SRP = "PASSWORD_SRP"
    PASSWORD = "PASSWORD"
    EMAIL_OTP = "EMAIL_OTP"
    SMS_OTP = "SMS_OTP"
    # WEB_AUTHN = "WEB_AUTHN"
    AUTHENTICATOR_MFA = "SOFTWARE_TOKEN_MFA"


class UserSignup(BaseModel):
    given_name: str = Field(max_length=50)
    family_name: str = Field(max_length=50)
    email: EmailStr
    phone_number: Annotated[str, MinLen(10)]
    password: Annotated[str, MinLen(8)]
    role: str


class UserVerify(BaseModel):
    email: EmailStr
    confirmation_code: Annotated[str, MaxLen(6)]


class UserSignin(BaseModel):
    email: EmailStr
    password: Optional[str] = Field(min_length=8)
    challenge_name: Challenge


class ConfirmForgotPassword(BaseModel):
    email: EmailStr
    confirmation_code: Annotated[str, MaxLen(6)]
    new_password: Annotated[str, MinLen(8)]


class ChangePassword(BaseModel):
    old_password: Annotated[str, MinLen(8)]
    new_password: Annotated[str, MinLen(8)]
    access_token: str


class RefreshToken(BaseModel):
    refresh_token: str
    access_token: str


class AccessToken(BaseModel):
    access_token: str


class RespondAuthChallenge(BaseModel):
    session_id: str
    challenge_name: Challenge
    email: EmailStr
    confirmation_code: str


class ConfirmSignup(BaseModel):
    email: EmailStr


class RegisterPasskey(BaseModel):
    access_token: str


class CompletePasskeyRegistration(BaseModel):
    access_token: str
    credential: dict
