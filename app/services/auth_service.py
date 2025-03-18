from fastapi import HTTPException
from fastapi.responses import JSONResponse
import botocore
from pydantic import EmailStr


from ..core.aws_cognito import AWS_Cognito
from ..models.user_model import ChangePassword, ConfirmForgotPassword, UserSignin, UserSignup, UserVerify, RespondAuthChallenge


class AuthService:
    def user_signup(user: UserSignup, cognito: AWS_Cognito):
        try:
            response = cognito.user_signup(user)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UsernameExistsException":
                raise HTTPException(status_code=409, detail="An account with the given email already exists")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                content = {"message": "User created successfully", "sub": response["UserSub"]}
                return JSONResponse(content=content, status_code=201)

    def verify_account(data: UserVerify, cognito: AWS_Cognito):
        try:
            response = cognito.verify_account(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "CodeMismatchException":
                raise HTTPException(status_code=400, detail="The provided code does not match the expected value.")
            elif e.response["Error"]["Code"] == "ExpiredCodeException":
                raise HTTPException(status_code=400, detail="The provided code has expired.")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User not found")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=200, detail="User already verified.")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return JSONResponse(content={"message": "Account verification successful"}, status_code=200)

    def resend_confirmation_code(email: EmailStr, cognito: AWS_Cognito):
        try:
            response = cognito.check_user_exists(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User deos not exist")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            try:
                response = cognito.resend_confirmation_code(email)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "UserNotFoundException":
                    raise HTTPException(status_code=404, detail="User not found")
                elif e.response["Error"]["Code"] == "LimitExceededException":
                    raise HTTPException(status_code=429, details="Limit exceeded")
                else:
                    raise HTTPException(status_code=500, detail=str(e))
            else:
                return JSONResponse(content={"message": "Confirmation code sent successfully"}, status_code=200)

    def user_signin(data: UserSignin, cognito: AWS_Cognito):
        try:
            response = cognito.user_signin(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "UserNotConfirmedException":
                raise HTTPException(status_code=403, detail="Please verify your account")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Incorrect username or password")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            content = {
                "message": "User signed in successfully",
                # "AccessToken": response["AuthenticationResult"]["AccessToken"],
                # "RefreshToken": response["AuthenticationResult"]["RefreshToken"],
                "data": response,
            }
            return JSONResponse(content=content, status_code=200)

    def forgot_password(email: EmailStr, cognito: AWS_Cognito):
        try:
            response = cognito.forgot_password(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User deos not exist")
            elif e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=403, detail="Unverified account")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return JSONResponse(content={"message": "Password reset code sent to your email address"}, status_code=200)

    def confirm_forgot_password(data: ConfirmForgotPassword, cognito: AWS_Cognito):
        try:
            response = cognito.confirm_forgot_password(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "ExpiredCodeException":
                raise HTTPException(status_code=403, detail="Code expired.")
            elif e.response["Error"]["Code"] == "CodeMismatchException":
                raise HTTPException(status_code=400, detail="Code does not match.")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return JSONResponse(content={"message": "Password reset successful"}, status_code=200)

    def change_password(data: ChangePassword, cognito: AWS_Cognito):
        try:
            response = cognito.change_password(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Access token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Incorrect username or password")
            elif e.response["Error"]["Code"] == "LimitExceededException":
                raise HTTPException(status_code=429, detail="Attempt limit exceeded, please try again later")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return JSONResponse(content={"message": "Password changed successfully"}, status_code=200)

    def new_access_token(refresh_token: str, cognito: AWS_Cognito):
        try:
            response = cognito.new_access_token(refresh_token)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Refresh token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid refresh token provided")
            elif e.response["Error"]["Code"] == "LimitExceededException":
                raise HTTPException(status_code=429, detail="Attempt limit exceeded, please try again later")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            content = {
                "message": "Refresh token generated successfully",
                "AccessToken": response["AuthenticationResult"]["AccessToken"],
                "ExpiresIn": response["AuthenticationResult"]["ExpiresIn"],
            }
            return JSONResponse(content=content, status_code=200)

    def logout(access_token: str, cognito: AWS_Cognito):
        try:
            response = cognito.logout(access_token)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Access token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "TooManyRequestsException":
                raise HTTPException(status_code=429, detail="Too many requests")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return

    def user_details(email: EmailStr, cognito: AWS_Cognito):
        try:
            response = cognito.check_user_exists(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User deos not exist")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            user = {}
            for attribute in response["UserAttributes"]:
                user[attribute["Name"]] = attribute["Value"]
            return JSONResponse(content=user, status_code=200)

    def auth_challenge_response(data: RespondAuthChallenge, cognito: AWS_Cognito):
        try:
            # breakpoint()
            response = cognito.send_response_challenge(data=data)
            print(response)
            return response
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
