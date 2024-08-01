import streamlit as st
import boto3
import jwt
import jwt.algorithms
from datetime import datetime, timedelta, timezone
from streamlit_feedback import streamlit_feedback
import login

UTC=timezone.utc


conversationID = None
parentMessageID = None

# Init configuration
login.retrieve_config_from_agent()
if 'messages' not in st.session_state:
    st.session_state.messages = []


if 'aws_credentials' not in st.session_state:
    st.session_state.aws_credentials = None



#INITIATE CHAT WITH Q APPLICATION
def new_chat_with_Q(prompt):
    global conversationID
    global parentMessageID
    try:
        amazon_q   = login.getCredentials(st.session_state["idc_jwt_token"]["idToken"])
        response = amazon_q.chat_sync(
            applicationId=login.AMAZON_Q_APP_ID,
            userMessage=prompt,
        )
        parentMessageID = response["systemMessageId"]
        conversationID = response["conversationId"]
        print(response)
        return response["systemMessage"]
    except Exception as e:
        print("Failed to chat with api: " + str(e))
        st.error("Failed to chat with api: " + str(e))



#CONTINUE CHAT WITH Q APPLICATION
def continue_chat_with_Q(prompt):
    global conversationID
    global parentMessageID
    try:
        amazon_q   = login.getCredentials(st.session_state["idc_jwt_token"]["idToken"])

        response = amazon_q.chat_sync( 
                applicationId=login.AMAZON_Q_APP_ID,
                userMessage=prompt,
                conversationId=conversationID,
                parentMessageId=parentMessageID,
        )
        parentMessageID = response["systemMessageId"]
        print(response)
        return response["systemMessage"]
    except Exception as e:
        print("Failed to chat with api: " + str(e))
        st.error("Failed to chat with api: " + str(e))  


#CLEAR CHAT
def clear_chat():
    global conversationID
    global parentMessageID
    conversationID = None
    parentMessageID = None
    st.session_state.messages = []
    st.rerun()




def logout():
    if 'token' in st.session_state:
        global conversationID
        global parentMessageID
        conversationID = None
        parentMessageID = None
        del st.session_state['aws_credentials']
        st.session_state.clear()  # This clears all session state variables

        # Prepare the Cognito logout URL
        cognito_domain = login.OAUTH_CONFIG["CognitoDomain"]
        client_id = login.OAUTH_CONFIG["ClientId"]
        external_dns = login.OAUTH_CONFIG["ExternalDns"]

        # Use the configured external DNS as the logout_uri
        logout_uri = f"https://{external_dns}"
        logout_url = f"https://{cognito_domain}/logout?client_id={client_id}&logout_uri={logout_uri}"

        # Redirect the user to the logout URL
        st.markdown(f"<meta http-equiv='refresh' content='0; url={logout_url}'/>", unsafe_allow_html=True)
    else:
        st.warning("No user logged in")




# Main chat application Interface
def chatApplicationComponent():
     #adding logo/username to the sidebar
    token = st.session_state["token"]
    user_name = jwt.decode(token["id_token"], options={"verify_signature": False})["cognito:username"]
    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = login.get_iam_oidc_token(token["id_token"])
       
    
    st.sidebar.text ("Welcome: " + user_name)
    st.markdown(
            f"""
            <style>
                [data-testid="stSidebarNav"]::before {{
                    content: "User: {user_name}";
                    margin-left: 20px;
                    margin-top: 20px;
                    font-size: 30px;
                    position: relative;
                    top: 100px;
                }}
            
            """,
            unsafe_allow_html=True
    )
    if st.sidebar.button("logout"):
        logout()
    global conversationID
    global parentMessageID
    st.markdown(
    """
        <style>
        button {
            height: auto;
            padding-top: 10px !important;
            padding-bottom: 10px !important;            
        }
        </style>
    """,
    unsafe_allow_html=True,
    )
    # st.write(st.session_state["idc_jwt_token"])
    # st.write(st.session_state['token'])
    # st.write(st.session_state['aws_credentials'])

    if "messages" not in st.session_state:
        st.session_state["messages"] = []
    
    if st.session_state.messages:
        if st.button("Clear Chat"):
            clear_chat()

    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    # React to user input
    prompt = st.chat_input("Ask Me a Question")

    # if st.button("Send"):
    if prompt:
        
        
        # Get assistant response
        if conversationID and parentMessageID:
            with st.chat_message("user"):
                st.markdown(prompt)
                # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.spinner("Waiting for response..."):
                system_response = continue_chat_with_Q(prompt)
                # Display assistant response
            with st.chat_message("system"):
                st.markdown(system_response)
            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": system_response})

        else:
            st.session_state.messages = []
            with st.chat_message("user"):
                st.markdown(prompt)
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.spinner("Waiting for response..."):
                system_response = new_chat_with_Q(prompt)
            
            # Display assistant response
            with st.chat_message("system"):
                st.markdown(system_response)
            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": system_response})


        st.rerun()
    
    
    if not st.session_state.messages and not conversationID and not parentMessageID:
        # Display the questions
        
        st.subheader("Ask Natural Language Questions Against IRS Form 1040 Instructions Guide:")
        st.write("Suggested Topics:")
        st.write("1. If I plan to move after filing my tax return, What should i File?")
        st.write("2. If my Filing Status is Single and i am under 65, what is the gross income limit?")
        st.write("3. How Should I Report Digital Asset Transactions?")
        st.write("4. Explain Line 6c to me") 
        

# Main to switch between login and cha.
def main():
    st.sidebar.subheader ("IRS Form 1040 Advisor App with Amazon Q") 
    global user_data

    if "token" not in st.session_state:
        oauth2 = login.configure_oauth_component()
        redirect_uri = f"https://{login.OAUTH_CONFIG["ExternalDns"]}/component/streamlit_oauth.authorize_button/index.html"
        # redirect_uri = f"http://localhost:8501/component/streamlit_oauth.authorize_button/index.html"
        result = oauth2.authorize_button("Login",scope="openid", pkce="S256", redirect_uri=redirect_uri)
        if result and "token" in result:
            # If authorization successful, save token in session state
            st.session_state.token = result.get("token")
            st.session_state["idc_jwt_token"] = login.get_iam_oidc_token(st.session_state.token["id_token"])            
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + \
                timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
            st.write("Login successful!!!", st.session_state["idc_jwt_token"])
            st.rerun()
    else:
        chatApplicationComponent()

if 'runpage' not in st.session_state:
    st.session_state.runpage = main
st.session_state.runpage()





















#////////////////  This commented code is of previous messages and conversation history///////////////////

# def list_conversations():
#     try:
#         client = boto3.client('qbusiness', region_name="us-west-2",
#                     aws_access_key_id=st.session_state['user']['accesskeyID'],
#                     aws_secret_access_key=st.session_state['user']['secretkey'],
#                     aws_session_token=st.session_state['user']['sessiontoken']
#                     )
#         response = client.list_conversations(
#         login.AMAZON_Q_APP_ID=login.AMAZON_Q_APP_ID,
#         maxResults=50,
#         userId=st.session_state['user']['userid']
#         )
#         return response["conversations"]
#     except Exception as e:
#         st.error("Failed to chat with api: " + str(e))

# def get_messages():
#     global parentMessageID
#     st.session_state.messages = []
#     client = boto3.client('qbusiness', region_name="us-west-2",
#                     aws_access_key_id=st.session_state['user']['accesskeyID'],
#                     aws_secret_access_key=st.session_state['user']['secretkey'],
#                     aws_session_token=st.session_state['user']['sessiontoken']
#                     )
#     response = client.list_messages(
#         login.AMAZON_Q_APP_ID=login.AMAZON_Q_APP_ID,
#         conversationId=conversationID,
#         maxResults=100,
#         userId=st.session_state['user']['userid']
#     )
#     previous_messages = response["messages"]
#     previous_messages= previous_messages[::-1]
#     for message in previous_messages:
#         role = message["type"]
#         content = message["body"]
#         if role == "USER":
#             st.session_state.messages.append({"role": "user", "content": content})
#         elif role == "SYSTEM":
#             st.session_state.messages.append({"role": "system", "content": content})
        
#     parentMessageID = response["messages"][0]["messageId"]


# def start_new_chat():
#     # Implement the functionality to start a new chat here
#     global conversationID
#     global parentMessageID
#     conversationID = None
#     parentMessageID = None
#     st.session_state.messages = []

#///////////////////////////////////////////////////////////////////////////////////////#




