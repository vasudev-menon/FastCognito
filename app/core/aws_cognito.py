import base64
from datetime import datetime, timezone
from os import getenv

import boto3
from pydantic import EmailStr

from ..models.user_model import ChangePassword, ConfirmForgotPassword, ConfirmSignup, RespondAuthChallenge, UserSignin, UserSignup, UserVerify
from .config import env_vars

AWS_REGION_NAME = env_vars.AWS_REGION_NAME
AWS_COGNITO_APP_CLIENT_ID = env_vars.AWS_COGNITO_APP_CLIENT_ID
AWS_COGNITO_USER_POOL_ID = env_vars.AWS_COGNITO_USER_POOL_ID

def calculate_secret_hash(client_id, client_secret, username):
    import base64
    import hashlib
    import hmac

    message = username + client_id
    dig = hmac.new(client_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

class AWS_Cognito:
    def __init__(self):
        self.client = boto3.client("cognito-idp", region_name=AWS_REGION_NAME)

    def user_signup(self, user: UserSignup):
        """
        The function `user_signup` signs up a user by sending their information to AWS Cognito for
        registration.

        :param user: The `user_signup` function takes a `UserSignup` object as a parameter. The
        `UserSignup` object likely contains information about a user who is signing up for a service or
        application. Based on the function implementation, the `UserSignup` object should have the
        following attributes:
        :type user: UserSignup
        :return: The function `user_signup` is returning the response object after signing up the user
        with the provided information such as email, password, given name, family name, phone number,
        and updated timestamp.
        """
        secret_hash = calculate_secret_hash(getenv("AWS_COGNITO_APP_CLIENT_ID"), getenv("CLIENT_SECRET"), user.email)
        response = self.client.sign_up(
            ClientId=AWS_COGNITO_APP_CLIENT_ID,
            Username=user.email,
            SecretHash=secret_hash,
            Password=user.password,
            UserAttributes=[
                {
                    "Name": "given_name",
                    "Value": user.given_name,
                },
                {
                    "Name": "family_name",
                    "Value": user.family_name,
                },
                {"Name": "phone_number", "Value": user.phone_number},
                {"Name": "updated_at", "Value": str(int(datetime.now(timezone.utc).timestamp()))},
                # {"Name": "email_verified", "Value": "True"},
            ],
        )

        return response

    def verify_account(self, data: UserVerify):
        """
        The function `verify_account` confirms a user sign-up using the provided email and confirmation
        code.

        :param data: The `data` parameter in the `verify_account` method is of type `UserVerify`. It
        likely contains information required to verify a user account, such as the user's email and
        confirmation code
        :type data: UserVerify
        :return: The `response` object is being returned from the `verify_account` method.
        """
        response = self.client.confirm_sign_up(
            ClientId=AWS_COGNITO_APP_CLIENT_ID,
            Username=data.email,
            ConfirmationCode=data.confirmation_code,
        )

        return response

    def resend_confirmation_code(self, email: EmailStr):
        response = self.client.resend_confirmation_code(ClientId=AWS_COGNITO_APP_CLIENT_ID, Username=email)

        return response

    def check_user_exists(self, email: EmailStr):
        response = self.client.admin_get_user(UserPoolId=AWS_COGNITO_USER_POOL_ID, Username=email)

        return response

    def user_signin(self, data: UserSignin):
        secret_hash = calculate_secret_hash(getenv("AWS_COGNITO_APP_CLIENT_ID"), getenv("CLIENT_SECRET"), data.email)
        response = self.client.initiate_auth(
            ClientId=AWS_COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_AUTH",
            AuthParameters={"USERNAME": data.email, "PASSWORD": data.password, "SECRET_HASH": secret_hash, "PREFERRED_CHALLENGE": data.challenge_name},
        )

        return response

    def forgot_password(self, email: EmailStr):
        response = self.client.forgot_password(ClientId=AWS_COGNITO_APP_CLIENT_ID, Username=email)

        return response

    def confirm_forgot_password(self, data: ConfirmForgotPassword):
        response = self.client.confirm_forgot_password(
            ClientId=AWS_COGNITO_APP_CLIENT_ID, Username=data.email, ConfirmationCode=data.confirmation_code, Password=data.new_password
        )

        return response

    def change_password(self, data: ChangePassword):
        response = self.client.change_password(
            PreviousPassword=data.old_password,
            ProposedPassword=data.new_password,
            AccessToken=data.access_token,
        )

        return response

    def new_access_token(self, refresh_token: str, email: EmailStr):
        secret_hash = calculate_secret_hash(getenv("AWS_COGNITO_APP_CLIENT_ID"), getenv("CLIENT_SECRET"), email)
        response = self.client.initiate_auth(
            ClientId=AWS_COGNITO_APP_CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token, "SECRET_HASH": secret_hash},
        )

        return response

    def logout(self, access_token: str):
        response = self.client.global_sign_out(AccessToken=access_token)

        return response

    def set_user_mfa(self, data: dict):
        # response = self.client.set_user_mfa_preference(
        #     UserPoolId=AWS_COGNITO_USER_POOL_ID,
        #     # Username=email,
        #     SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": False},
        #     AccessToken=data.access_token,
        # )
        # print(response)
        # Generate a software token
        # response = self.client.get_software_token(
        #     AccessToken=data.access_token,
        # )
        # software_token = response["SessionToken"]
        # secret_token = response["SecretCode"]

        # Generate a passkey (TOTP secret key)
        totp_secret_key_response = self.client.associate_software_token(AccessToken=data.get("access_token"))

        # totp_resp = {"software_token": software_token, "totp_secret_key": totp_secret_key}
        # return software_token, totp_secret_key

        # return response
        if totp_secret_key_response["SecretCode"] is not None:
            return totp_secret_key_response

    def send_response_challenge(self, data: RespondAuthChallenge):
        secret_hash = calculate_secret_hash(getenv("AWS_COGNITO_APP_CLIENT_ID"), getenv("CLIENT_SECRET"), data.email)
        challenge_resp = {}
        if data.challenge_name == "EMAIL_OTP":
            challenge_resp = {
                "EMAIL_OTP_CODE": data.confirmation_code,
                "USERNAME": data.email,
                "SECRET_HASH": secret_hash,
            }
        if data.challenge_name == "SMS_OTP":
            challenge_resp = {
                "SMS_OTP_CODE": data.confirmation_code,
                "USERNAME": data.email,
                "SECRET_HASH": secret_hash,
            }

        respond_to_auth_challenge_params = {
            "ClientId": AWS_COGNITO_APP_CLIENT_ID,
            "UserPoolId": AWS_COGNITO_USER_POOL_ID,
            "ChallengeName": data.challenge_name,
            "Session": data.session_id,
            "ChallengeResponses": challenge_resp,
        }
        response = self.client.admin_respond_to_auth_challenge(**respond_to_auth_challenge_params)
        print(response)
        # Check if the authentication was successful
        if response.get("AuthenticationResult") is not None:
            # Get the access token and other authentication results
            access_token = response["AuthenticationResult"]["AccessToken"]
            refresh_token = response["AuthenticationResult"]["RefreshToken"]

            print("Authentication successful!")
            print("Access token:", access_token)
            print("Refresh token:", refresh_token)

            return response.get("AuthenticationResult")
        else:
            print("Authentication failed!")
            return None

    def signup_confirm_admin(self, data: ConfirmSignup):
        response = self.client.admin_confirm_sign_up(
            UserPoolId=AWS_COGNITO_USER_POOL_ID,
            Username=data.email,
        )
        return response

    def verify_software_token_mfa(self, data: dict):
        response = self.client.verify_software_token(
            AccessToken=data.get("access_token"),
            UserCode=data.get("code"),
        )
        return response