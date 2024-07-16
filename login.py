import streamlit as st
import boto3
from streamlit_oauth import OAuth2Component
import jwt
import jwt.algorithms
from datetime import datetime

CLIENT_ID = st.secrets["ClientId"]
REGION = st.secrets["REGION"]
COGNITO_DOMAIN = st.secrets["CognitoDomain"]
IDC_APPLICATION_ID = st.secrets["IDC_APPLICATION_ID"]
IAM_ROLE = st.secrets["IAM_ROLE"]


# Function use to authenticate user credentials from Amazon Cognito
def configure_oauth_component():
    """
    Configure the OAuth2 component for Cognito
    """
    cognito_domain = COGNITO_DOMAIN
    authorize_url = f"https://{cognito_domain}/oauth2/authorize"
    token_url = f"https://{cognito_domain}/oauth2/token"
    refresh_token_url = f"https://{cognito_domain}/oauth2/token"
    revoke_token_url = f"https://{cognito_domain}/oauth2/revoke"
    client_id = CLIENT_ID
    return OAuth2Component(
        client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url
    )


def get_iam_oidc_token(id_token):
    """
    Get the IAM OIDC token using the ID token retrieved from Cognito
    """
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion=id_token,
    )
    return response


def assume_role_with_token(iam_token):
    """
    Assume IAM role with the IAM OIDC idToken
    """
    decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
    sts_client = boto3.client("sts", region_name=REGION)
    response = sts_client.assume_role(
        RoleArn=IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token["sts:identity_context"],
            }
        ],
    )
    st.session_state.aws_credentials = response["Credentials"]



# This method create the Q client
def getCredentials(idc_id_token: str):
    # """
    # Create the Q client using the identity-aware AWS Session.
    # """
    if not st.session_state.aws_credentials:
        assume_role_with_token(idc_id_token)


    
    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    amazon_q = session.client("qbusiness", REGION)

    sts_client = boto3.client('sts',
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
        )
    Userid = sts_client.get_caller_identity()
    return amazon_q, Userid["UserId"]







