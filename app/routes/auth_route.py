from fastapi import APIRouter, Depends, status
from pydantic import EmailStr

from ..core.aws_cognito import AWS_Cognito
from ..core.dependencies import get_aws_cognito
from ..models.user_model import (
    AccessToken,
    ChangePassword,
    ConfirmForgotPassword,
    ConfirmSignup,
    RefreshToken,
    RespondAuthChallenge,
    UserSignin,
    UserSignup,
    UserVerify,
)
from ..services.auth_service import AuthService

auth_router = APIRouter(prefix="/api/auth")


# USER SIGNUP
@auth_router.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup_user(user: UserSignup, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    return AuthService.user_signup(user, cognito)


@auth_router.post("/verify_account", status_code=status.HTTP_200_OK, tags=["Auth"])
async def verify_account(
    data: UserVerify,
    cognito: AWS_Cognito = Depends(get_aws_cognito),
):
    """
        The function `verify_account` verifies a user account using AWS Cognito. Use this API after using `signup api` after you receive the code in `email/sms`. OTP code is only valid for 15 mins. Past the 15 mins, you will need to resend the code using `resend_confirmation_code` API.
    `

        :param data: The `data` parameter in the `verify_account` function is of type `UserVerify`. It
        likely contains information needed to verify a user account, such as user credentials or
        verification codes
        :type data: UserVerify
        :param cognito: The `cognito` parameter in the `verify_account` function is an instance of the
        `AWS_Cognito` class. It is likely used for interacting with AWS Cognito services for user
        authentication and management. The `get_aws_cognito` function is probably a dependency injector that
        provides an instance
        :type cognito: AWS_Cognito
        :return: The `verify_account` function is returning the result of calling the `verify_account`
        method from the `AuthService` class with the provided `data` and `cognito` parameters.
    """
    return AuthService.verify_account(data, cognito)


# RESEND CONFIRMATION CODE
@auth_router.post("/resend_confirmation_code", status_code=status.HTTP_200_OK, tags=["Auth"])
async def resend_confirmation_code(email: EmailStr, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `resend_confirmation_code` asynchronously resends a confirmation code to the specified
    email using AWS Cognito.

    :param email: The `email` parameter is of type `EmailStr`, which is a Pydantic model for validating
    email addresses. It ensures that the email provided is in a valid format
    :type email: EmailStr
    :param cognito: The `cognito` parameter in the `resend_confirmation_code` function is an instance of
    the `AWS_Cognito` class, which is likely used for interacting with AWS Cognito services. It is
    obtained as a dependency using the `Depends` function with the `get_aws_cognito
    :type cognito: AWS_Cognito
    :return: The `resend_confirmation_code` function is returning the result of calling the
    `resend_confirmation_code` method from the `AuthService` class with the provided `email` and
    `cognito` parameters.
    """
    return AuthService.resend_confirmation_code(email, cognito)


# USER SIGNIN
@auth_router.post("/signin", status_code=status.HTTP_200_OK, tags=["Auth"])
async def signin(data: UserSignin, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The `signin` function takes user sign-in data and AWS Cognito dependency to authenticate the user
    using the `AuthService.user_signin` method.

    :param data: The `data` parameter is of type `UserSignin`, which likely contains the user's
    sign-in information such as username and password. It is used as input for the `signin` function
    :type data: UserSignin
    :param cognito: The `cognito` parameter is of type `AWS_Cognito` and is obtained by using the
    `Depends` function with the `get_aws_cognito` dependency. This parameter is likely used for
    interacting with AWS Cognito services for user authentication and management
    :type cognito: AWS_Cognito
    :return: The `signin` function is returning the result of calling the `user_signin` method of the
    `AuthService` class with the provided `data` and `cognito` parameters.
    """
    return AuthService.user_signin(data, cognito)


# FORGOT PASSWORD
@auth_router.post("/forgot_password", status_code=status.HTTP_200_OK, tags=["Auth"])
async def forgot_password(email: EmailStr, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `forgot_password` triggers the forgot password flow for a user with the specified email
    using AWS Cognito.

    :param email: The `email` parameter is of type `EmailStr`, which is a Pydantic model for validating
    email addresses. It ensures that the input provided is a valid email address format
    :type email: EmailStr
    :param cognito: The `cognito` parameter in the `forgot_password` function seems to be an instance of
    the `AWS_Cognito` class, likely used for interacting with AWS Cognito services. This parameter is
    obtained as a dependency using the `Depends` function with the `get_aws_cognito`
    :type cognito: AWS_Cognito
    :return: The `forgot_password` function is returning the result of calling the `forgot_password`
    method of the `AuthService` class with the `email` and `cognito` parameters.
    """
    return AuthService.forgot_password(email, cognito)


# CONFIRM FORGOT PASSWORD
@auth_router.post("/confirm_forgot_password", status_code=status.HTTP_200_OK, tags=["Auth"])
async def confirm_forgot_password(data: ConfirmForgotPassword, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `confirm_forgot_password` confirms a forgotten password using AWS Cognito
    authentication service.

    :param data: The `data` parameter in the `confirm_forgot_password` function likely contains
    information related to confirming a forgot password request. It could include details such as the
    user's email or username, the confirmation code sent to the user, and the new password that the user
    wants to set. This data is
    :type data: ConfirmForgotPassword
    :param cognito: The `cognito` parameter in the `confirm_forgot_password` function is an instance of
    the `AWS_Cognito` class. It is likely used for interacting with the AWS Cognito service, which is a
    user authentication and access control service provided by Amazon Web Services. This parameter is
    likely used
    :type cognito: AWS_Cognito
    :return: The `confirm_forgot_password` function is returning the result of calling the
    `confirm_forgot_password` method from the `AuthService` class with the provided `data` and `cognito`
    parameters.
    """
    return AuthService.confirm_forgot_password(data, cognito)


# CHANGE PASSWORD
@auth_router.post("/change_password", status_code=status.HTTP_200_OK, tags=["Auth"])
async def change_password(data: ChangePassword, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `change_password` asynchronously changes a user's password using AWS Cognito.

    :param data: The `data` parameter seems to be of type `ChangePassword`, which likely contains
    information required to change a user's password. It could include fields such as the old password,
    new password, and any other necessary details for the password change process
    :type data: ChangePassword
    :param cognito: The `cognito` parameter in the `change_password` function is of type `AWS_Cognito`,
    which is likely a dependency injected using `Depends(get_aws_cognito)`. This parameter is used in
    the function to interact with AWS Cognito services for changing the user's password
    :type cognito: AWS_Cognito
    :return: The `change_password` function is returning the result of calling the
    `AuthService.change_password` method with the provided `data` and `cognito` parameters.
    """
    return AuthService.change_password(data, cognito)


# GENERATE NEW ACCESS TOKEN
@auth_router.post("/new_token", status_code=status.HTTP_200_OK, tags=["Auth"])
async def new_access_token(refresh_token: RefreshToken, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    This function generates a new access token using a refresh token and AWS Cognito authentication
    service.

    :param refresh_token: The `refresh_token` parameter is an object representing a refresh token used
    for obtaining a new access token in the context of authentication and authorization processes. It is
    typically issued by an authentication server and can be used to request a new access token without
    requiring the user to re-enter their credentials
    :type refresh_token: RefreshToken
    :param cognito: The `cognito` parameter in the `new_access_token` function is an instance of the
    `AWS_Cognito` class. It is obtained as a dependency using the `Depends` function with the
    `get_aws_cognito` function. This parameter likely represents the AWS Cognito service that
    :type cognito: AWS_Cognito
    :return: The function `new_access_token` is returning the result of calling
    `AuthService.new_access_token` with the `refresh_token` extracted from the `RefreshToken` object and
    the `cognito` object obtained from the `get_aws_cognito` dependency.
    """
    return AuthService.new_access_token(refresh_token.refresh_token, cognito, refresh_token.access_token)


# LOGOUT
@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["Auth"])
async def logout(access_token: AccessToken, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The `logout` function logs out a user by calling the `AuthService.logout` method with the provided
    access token and AWS Cognito dependency.

    :param access_token: The `access_token` parameter is an object of type `AccessToken`, which is
    likely used to authenticate and authorize a user's access to certain resources or services. In the
    provided code snippet, the `logout` function takes this `access_token` as an argument to perform a
    logout operation, possibly invalid
    :type access_token: AccessToken
    :param cognito: The `cognito` parameter in the `logout` function is an instance of the `AWS_Cognito`
    class, which is obtained by calling the `get_aws_cognito` dependency. This parameter is used in the
    function to interact with the AWS Cognito service for logging out the user associated
    :type cognito: AWS_Cognito
    :return: The `logout` function is returning the result of calling the `AuthService.logout` method
    with the `access_token.access_token` and `cognito` parameters.
    """
    return AuthService.logout(access_token.access_token, cognito)


# GET USER DETAILS
@auth_router.get("/user_details", status_code=status.HTTP_200_OK, tags=["Auth"])
async def user_details(email: EmailStr, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `user_details` retrieves user details using the provided email and AWS Cognito
    authentication.

    :param email: The `email` parameter is of type `EmailStr`, which is a Pydantic model for validating
    email addresses. It ensures that the input provided is a valid email address format
    :type email: EmailStr
    :param cognito: The `cognito` parameter in the `user_details` function is of type `AWS_Cognito`,
    which is likely a dependency that provides access to AWS Cognito services. This parameter is
    obtained using the `Depends` function, which indicates that it is a dependency injection that
    retrieves the AWS C
    :type cognito: AWS_Cognito
    :return: The `user_details` function is returning the user details associated with the provided
    email address using the AWS Cognito service.
    """
    return AuthService.user_details(email, cognito)


# Respond to Auth Challenge (Password, OTP (Email/Phone))
@auth_router.post("/respond_to_auth_challenge", status_code=status.HTTP_200_OK, tags=["Auth"])
async def respond_to_auth_challenge(data: RespondAuthChallenge, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    This Python function responds to an authentication challenge using AWS Cognito authentication
    service.

    :param data: The `data` parameter in the `respond_to_auth_challenge` function is of type
    `RespondAuthChallenge`. This parameter likely contains information related to an authentication
    challenge that needs to be responded to
    :type data: RespondAuthChallenge
    :param cognito: The `cognito` parameter is an instance of the `AWS_Cognito` class, which is likely a
    dependency injection for accessing AWS Cognito services in the `respond_to_auth_challenge` function.
    It is used to interact with AWS Cognito for handling authentication challenges
    :type cognito: AWS_Cognito
    :return: The function `respond_to_auth_challenge` is returning the result of calling the
    `auth_challenge_response` method from the `AuthService` class with the provided `data` and `cognito`
    parameters.
    """
    return AuthService.auth_challenge_response(data, cognito)


@auth_router.post("/confirm_user_signup", status_code=status.HTTP_200_OK, tags=["Auth"])
async def confirm_user_signup(data: ConfirmSignup, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    The function `confirm_user_signup` confirms a user's signup using AWS Cognito. Use this API if you're getting the response `Verify the User` from the Cognito API after using self-signup api


    :param data: The `data` parameter in the `confirm_user_signup` function likely represents the
    information needed to confirm a user's signup. It could include data such as the user's email
    address, confirmation code, or any other details required to verify the user's identity and complete
    the signup process. The exact structure
    :type data: ConfirmSignup
    :param cognito: The `cognito` parameter in the `confirm_user_signup` function is of type
    `AWS_Cognito`, which is likely a dependency injection for accessing AWS Cognito services. This
    parameter is obtained using the `Depends` function with the `get_aws_cognito` function as an
    argument
    :type cognito: AWS_Cognito
    """
    return AuthService.admin_confirm_user_signup(data, cognito)


@auth_router.post("/add_mfa", status_code=status.HTTP_200_OK, tags=["Auth"])
async def add_mfa_user(token: str | None, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    data = {}
    if token:
        data["access_token"] = token
        return AuthService.add_mfa_to_user(data, cognito)
    return "Missing Token", 401


@auth_router.post("/verify_mfa", status_code=status.HTTP_200_OK, tags=["Auth"])
async def verify_mfa(token: str | None, code: str | None, cognito: AWS_Cognito = Depends(get_aws_cognito)):
    """
    This Python function `verify_mfa` handles the verification of multi-factor authentication using
    token and code inputs after using `/add_mfa` api to setup intially 2FA on authenticator apps via QR code.

    :param token: The `token` parameter in the `verify_mfa` endpoint is a string that represents an
    access token. It is used for authentication and authorization purposes when verifying the
    multi-factor authentication (MFA) code
    :type token: str | None
    :param code: The `code` parameter in the `verify_mfa` endpoint refers to the multi-factor
    authentication code that the user provides to verify their identity. This code is typically
    generated by an authenticator app or sent to the user via SMS or email as part of the two-factor
    authentication process. The user needs
    :type code: str | None
    :param cognito: The parameter `cognito` in the `verify_mfa` function is of type `AWS_Cognito`, which
    is likely a dependency that provides access to AWS Cognito services for user authentication and
    management. This dependency is obtained using the `Depends` function with the `get_aws_cognito
    :type cognito: AWS_Cognito
    :return: The code snippet is a FastAPI endpoint for verifying multi-factor authentication (MFA)
    using AWS Cognito. If both the `token` and `code` parameters are provided in the request, the
    function `verify_mfa` from the `AuthService` class is called with the provided data and the AWS
    Cognito instance. The result of this function call is returned.
    """
    data = {}
    if token and code:
        data["access_token"] = token
        data["code"] = code

        return AuthService.verify_mfa(data, cognito)
    return "Missing Token and Code", 401
