import boto3
from pydantic import EmailStr
from datetime import datetime, timezone


from ..models.user_model import ChangePassword, ConfirmForgotPassword, UserSignin, UserSignup, UserVerify, RespondAuthChallenge
from .config import env_vars
from os import getenv

AWS_REGION_NAME = env_vars.AWS_REGION_NAME
AWS_COGNITO_APP_CLIENT_ID = env_vars.AWS_COGNITO_APP_CLIENT_ID
AWS_COGNITO_USER_POOL_ID = env_vars.AWS_COGNITO_USER_POOL_ID

def calculate_secret_hash(client_id, client_secret, username):
    import hmac
    import hashlib
    import base64

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

    def new_access_token(self, refresh_token: str):
        response = self.client.initiate_auth(
            ClientId=AWS_COGNITO_APP_CLIENT_ID,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
            },
        )

        return response

    def logout(self, access_token: str):
        response = self.client.global_sign_out(AccessToken=access_token)

        return response

    def set_user_mfa_preference(self, email: EmailStr, mfa_enabled: bool):
        response = self.client.admin_set_user_mfa_preference(
            UserPoolId=AWS_COGNITO_USER_POOL_ID,
            Username=email,
            SoftwareTokenMfaConfiguration="ENABLED" if mfa_enabled else "DISABLED",
        )

        return response

    def send_response_challenge(self, data: RespondAuthChallenge):
        respond_to_auth_challenge_params = {
            "ClientId": AWS_COGNITO_APP_CLIENT_ID,
            "UserPoolId": AWS_COGNITO_USER_POOL_ID,
            "ChallengeName": data.challenge_name,
            "Session": data.session_id,
            "ChallengeResponses": {
                "ANSWER": data.confirmation_code,
                "USERNAME": data.email,
            },
        }
        response = self.client.admin_respond_to_auth_challenge(**respond_to_auth_challenge_params)
        print(response)
        # Check if the authentication was successful
        if response.get("AuthenticationResult"):
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
