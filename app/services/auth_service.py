from io import BytesIO

import botocore
import qrcode
from fastapi import HTTPException, Response
from fastapi.responses import JSONResponse
from otpauth import TOTP
from pydantic import EmailStr
from qrcode.image.pure import PyPNGImage

from ..core.aws_cognito import AWS_Cognito
from ..models.user_model import ChangePassword, ConfirmForgotPassword, ConfirmSignup, RespondAuthChallenge, UserSignin, UserSignup, UserVerify


class AuthService:
    def user_signup(user: UserSignup, cognito: AWS_Cognito):
        """
        The function `user_signup` handles user sign-up using AWS Cognito, checking for existing email
        accounts and returning appropriate HTTP responses.

        :param user: The `user` parameter in the `user_signup` function is of type `UserSignup`, which
        likely contains information about the user signing up, such as their email, password, and any
        other relevant details needed for user registration
        :type user: UserSignup
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides user
        authentication and authorization functionalities. It is used in the code snippet provided for
        handling user sign-up operations
        :type cognito: AWS_Cognito
        :return: a JSON response with a message indicating that the user was created successfully, along
        with the user's sub (subject) identifier. The status code of the response is 201, indicating
        that the request was successful and a new resource has been created.
        """
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
        """
        The function `verify_account` verifies a user account using AWS Cognito and handles different
        exceptions based on the error codes returned.

        :param data: The `data` parameter in the `verify_account` function likely represents user
        verification data, such as a verification code or token, that is being used to verify a user
        account. This data is passed to the function along with an instance of the `AWS_Cognito` class
        (represented by the `
        :type data: UserVerify
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that is used for
        user authentication and authorization in your application. It is likely a part of the AWS SDK or
        a custom implementation that interacts with the AWS Cognito service to verify user accounts
        :type cognito: AWS_Cognito
        :return: The function `verify_account` is returning a JSONResponse with content `{"message":
        "Account verification successful"}` and a status code of 200 if the account verification is
        successful.
        """
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
        """
        The function `resend_confirmation_code` checks if a user exists in AWS Cognito and resends a
        confirmation code if the user exists.

        :param email: The `email` parameter is of type `EmailStr`, which is likely a custom data type
        representing an email address. It is used as the email address of the user for whom the
        confirmation code needs to be resent
        :type email: EmailStr
        :param cognito: The `cognito` parameter in the `resend_confirmation_code` function likely refers
        to an object or instance of a class that interacts with AWS Cognito services. It seems to have
        methods like `check_user_exists` and `resend_confirmation_code` that interact with AWS Cognito
        to perform operations
        :type cognito: AWS_Cognito
        :return: a JSON response with the content {"message": "Confirmation code sent successfully"} and
        a status code of 200.
        """
        try:
            response = cognito.check_user_exists(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
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
        """
        The function `user_signin` handles user sign-in requests using AWS Cognito and returns
        appropriate HTTP responses based on different error scenarios.

        :param data: The `data` parameter in the `user_signin` function represents the user sign-in data
        that is being passed to the function. It likely includes information such as the user's
        username, password, and any additional authentication details required for the sign-in process.
        This data is used by the function to
        :type data: UserSignin
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides user
        authentication and authorization functionalities. It is used in the code snippet to handle user
        sign-in operations by interacting with the AWS Cognito service
        :type cognito: AWS_Cognito
        :return: The function `user_signin` is returning a JSON response with a message indicating
        whether the user signed in successfully or not, along with relevant data. The specific content
        being returned depends on the conditions met during the execution of the function. If the user
        signs in successfully and the challenge name is "PASSWORD", the response includes the message
        "User signed in successfully" and the authentication result data. Otherwise,
        """
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
            if response.get("AuthenticationResult") is not None and data.challenge_name == "PASSWORD":
                content = {
                    "message": "User signed in successfully",
                    # "AccessToken": response["AuthenticationResult"]["AccessToken"],
                    # "RefreshToken": response["AuthenticationResult"]["RefreshToken"],
                    "data": response.get("AuthenticationResult"),
                }
            else:
                content = {
                    "message": "User signed in successfully",
                    "data": response,
                }
            return JSONResponse(content=content, status_code=200)

    def forgot_password(email: EmailStr, cognito: AWS_Cognito):
        """
        The function `forgot_password` sends a password reset code to a user's email address using AWS
        Cognito, handling different exceptions based on the error codes.

        :param email: The `email` parameter is the email address of the user who wants to reset their
        password
        :type email: EmailStr
        :param cognito: AWS_Cognito is an object representing an AWS Cognito service that allows
        interaction with user pools for authentication and authorization in AWS
        :type cognito: AWS_Cognito
        :return: A JSON response with the message "Password reset code sent to your email address" and a
        status code of 200 is being returned.
        """
        try:
            response = cognito.forgot_password(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=403, detail="Unverified account")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return JSONResponse(content={"message": "Password reset code sent to your email address"}, status_code=200)

    def confirm_forgot_password(data: ConfirmForgotPassword, cognito: AWS_Cognito):
        """
        The function `confirm_forgot_password` confirms a forgotten password using AWS Cognito and
        handles different exceptions based on error codes.

        :param data: The `data` parameter in the `confirm_forgot_password` function likely contains
        information related to confirming a forgot password request. It could include details such as
        the user's email or username, the confirmation code provided by the user, and possibly other
        relevant information needed to confirm the password reset. This data
        :type data: ConfirmForgotPassword
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides
        authentication, authorization, and user management for web and mobile applications. It is used
        to interact with the AWS Cognito service to confirm a forgot password request for a user
        :type cognito: AWS_Cognito
        :return: A JSON response with the content {"message": "Password reset successful"} and a status
        code of 200 is being returned.
        """
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
        """
        The function `change_password` handles changing a user's password in AWS Cognito and raises
        appropriate HTTP exceptions based on different error scenarios.

        :param data: The `data` parameter in the `change_password` function likely contains information
        required to change a user's password, such as the user's current password and the new password.
        It is of type `ChangePassword`, which could be a custom data class or structure defined
        elsewhere in the codebase. This
        :type data: ChangePassword
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that allows
        interaction with the AWS Cognito user pools for managing user authentication and authorization
        :type cognito: AWS_Cognito
        :return: A JSON response with the content {"message": "Password changed successfully"} and a
        status code of 200 is being returned.
        """
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

    def new_access_token(refresh_token: str, cognito: AWS_Cognito, access_token: str):
        """
        The function `new_access_token` generates a new access token using a refresh token in AWS
        Cognito and handles different exceptions accordingly.

        :param refresh_token: A refresh token is a special token used in OAuth2 authentication to obtain
        a new access token without requiring the user to re-enter their credentials. It is typically
        used to extend the validity of an access token or to obtain a new one after the current one
        expires
        :type refresh_token: str
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides
        authentication, authorization, and user management for web and mobile apps. It is used in the
        code snippet to interact with AWS Cognito to generate a new access token using a refresh token
        :type cognito: AWS_Cognito
        :return: The function `new_access_token` is returning a JSON response containing a message
        indicating that the refresh token was generated successfully, along with the access token and
        its expiration time. The response includes the access token and its expiration time in seconds.
        """
        try:
            response = cognito.new_access_token(refresh_token, access_token)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Refresh token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail=str(e))
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
        """
        The `logout` function logs out a user by calling the `logout` method of an AWS Cognito object,
        handling specific exceptions and returning nothing if successful.

        :param access_token: An access token is a credential used to access protected resources on
        behalf of a user. It is typically obtained after a user successfully logs in and authorizes
        access to their data. In the context of the provided code snippet, the `access_token` parameter
        is a string representing the access token that needs to
        :type access_token: str
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides
        methods for user authentication, authorization, and user management in AWS applications. In the
        provided code snippet, the `logout` function takes an `access_token` (a string) and a `cognito`
        object as parameters. The
        :type cognito: AWS_Cognito
        :return: If the `try` block successfully executes without raising any exceptions, the function
        will return `None`.
        """
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
        """
        This Python function checks if a user exists in AWS Cognito using the provided email and returns
        the user details if found.

        :param email: The `email` parameter is of type `EmailStr`, which is a Pydantic data type for
        validating email addresses. It ensures that the input provided is a valid email address format
        :type email: EmailStr
        :param cognito: AWS_Cognito is a class or object representing an AWS Cognito service that
        provides methods for interacting with user data and authentication in AWS Cognito. It likely has
        a method called `check_user_exists(email)` that checks if a user with the given email exists in
        the Cognito user pool
        :type cognito: AWS_Cognito
        :return: A JSON response containing the user details retrieved from AWS Cognito is being
        returned. The user details are extracted from the response object and formatted into a
        dictionary before being returned with a status code of 200.
        """
        try:
            response = cognito.check_user_exists(email)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            user = {}
            for attribute in response["UserAttributes"]:
                user[attribute["Name"]] = attribute["Value"]
            return JSONResponse(content=user, status_code=200)

    def auth_challenge_response(data: RespondAuthChallenge, cognito: AWS_Cognito):
        """
        The function `auth_challenge_response` sends a response to an authentication challenge using AWS
        Cognito and handles exceptions by raising an HTTPException with status code 500.

        :param data: `RespondAuthChallenge` is likely a data structure or object containing information
        needed to respond to an authentication challenge. It could include things like user input,
        tokens, or other authentication-related data
        :type data: RespondAuthChallenge
        :param cognito: AWS_Cognito is an object representing the AWS Cognito service that provides
        methods for interacting with the Cognito service, such as sending challenge responses
        :type cognito: AWS_Cognito
        :return: the response received after sending a challenge response to AWS Cognito.
        """
        try:
            response = cognito.send_response_challenge(data=data)
            print(response)
            return response
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def admin_confirm_user_signup(data: ConfirmSignup, cognito: AWS_Cognito):
        """
        The function `admin_confirm_user_signup` confirms a user's signup using AWS Cognito and handles
        different exceptions based on the error code.

        :param data: The `data` parameter in the `admin_confirm_user_signup` function likely contains
        information related to confirming a user signup, such as the user's email address, confirmation
        code, or other necessary details for the confirmation process. This data is used as input for
        the `cognito.signup_confirm_admin` method
        :type data: ConfirmSignup
        :param cognito: The `cognito` parameter in the `admin_confirm_user_signup` function is an
        instance of the `AWS_Cognito` class, which is likely a wrapper or interface for interacting with
        AWS Cognito services. This parameter is used to call the `signup_confirm_admin` method to
        confirm a user's
        :type cognito: AWS_Cognito
        """
        try:
            response = cognito.signup_confirm_admin(data=data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Access token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "TooManyRequestsException":
                raise HTTPException(status_code=429, detail="Too many requests")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return response

    def add_mfa_to_user(data: dict, cognito: AWS_Cognito):
        try:
            response = cognito.set_user_mfa(data)

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Access token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "UserNotConfirmedException":
                raise HTTPException(status_code=404, detail="User not Confirmed")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            if response.get("SecretCode"):
                # use b32 encode directly on secret code returned from cognito
                totp = TOTP.from_b32encode(response.get("SecretCode"))
                print(totp)
                final_qr_code = totp.to_uri("Billimd_Cred_Platform:us-east-23dtuojzv6.auth.us-east-2.amazoncognito.com", "Authlib")
                img = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                img.add_data(final_qr_code)
                img.make(fit=True)
                img = img.make_image(fill_color="black", back_color="white", image_factory=PyPNGImage)
                buf = BytesIO()
                img.save(buf)

                print(response.get("SecretCode"))

                return Response(buf.getvalue(), media_type="image/png")

    def verify_mfa(data: dict, cognito: AWS_Cognito):
        try:
            response = cognito.verify_software_token_mfa(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail="Access token provided has wrong format")
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "TooManyRequestsException":
                raise HTTPException(status_code=429, detail="Too many requests")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "PasswordResetRequiredException":
                raise HTTPException(status_code=404, detail="Password Reset Required")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return response

    def register_for_passkeys(data: dict, cognito: AWS_Cognito):
        try:
            response = cognito.register_user_passkey(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail=str(e))
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "TooManyRequestsException":
                raise HTTPException(status_code=429, detail="Too many requests")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "WebAuthnNotEnabledException":
                raise HTTPException(status_code=404, detail="Web Auth Not Enabled!")
            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return response

    def verify_passkey_registration(data: dict, cognito: AWS_Cognito):
        try:
            response = cognito.verify_user_passkey(data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException":
                raise HTTPException(status_code=400, detail=str(e))
            elif e.response["Error"]["Code"] == "NotAuthorizedException":
                raise HTTPException(status_code=401, detail="Invalid access token provided")
            elif e.response["Error"]["Code"] == "TooManyRequestsException":
                raise HTTPException(status_code=429, detail="Too many requests")
            elif e.response["Error"]["Code"] == "UserNotFoundException":
                raise HTTPException(status_code=404, detail="User does not exist")
            elif e.response["Error"]["Code"] == "WebAuthnNotEnabledException":
                raise HTTPException(status_code=404, detail="Web Auth Not Enabled!")
            elif e.response["Error"]["Code"] == "WebAuthnChallengeNotFoundException":
                raise HTTPException(status_code=404, detail="Web Auth Challenge Not Found!")

            else:
                raise HTTPException(status_code=500, detail=str(e))
        else:
            return response
