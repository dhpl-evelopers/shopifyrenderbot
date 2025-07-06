import streamlit as st
import bcrypt
import os
import time  # Add this line with other imports
import requests
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
import json
import uuid
import urllib.parse
from datetime import datetime
from authlib.integrations.requests_client import OAuth2Session
from config import Config
import logging
import re
import base64
import threading


def warm_up_bot():
    try:
        resp = requests.post(Config.CHAT_API_URL, json={"question": "ping"}, timeout=5)
        print("✅ Warm-up complete:", resp.status_code)
    except Exception as e:
        print("⚠️ Warm-up failed:", e)


from image_storage import ImageStorage
image_storage = ImageStorage()

if "sidebar_expanded" not in st.session_state:
    st.session_state.sidebar_expanded = True


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
st.markdown("""
<style>
/* ✅ Hide Streamlit branding and GitHub/Fork buttons */
#MainMenu, footer {
    display: none !important;
    visibility: hidden !important;
}

/* ✅ Only hide GitHub/Fork toolbar without affecting sidebar toggle */
[data-testid="stToolbarActions"] {
    display: none !important;
}

/* ✅ Ensure sidebar toggle arrow (collapsedControl) is always visible */
button[data-testid="collapsedControl"] {
    display: block !important;
    visibility: visible !important;
    position: fixed !important;
    top: 16px;
    left: 16px;
    z-index: 9999;
    background-color: white !important;
    border: 1px solid #ccc !important;
    border-radius: 6px !important;
    padding: 6px 10px !important;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
</style>
""", unsafe_allow_html=True)


# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="RINGS & I - AI Ring Advisor",
    page_icon="💍",
    layout="wide",  # <--- changed from 'centered' to 'wide'
    initial_sidebar_state="expanded",
    menu_items=None
)

# Apply CSS fix to all input components
st.markdown("""
    <style>
    /* Remove extra container border */
    div[data-baseweb="input"] {
        border: none !important;
        box-shadow: none !important;
    }

    input:focus, textarea:focus {
        outline: none !important;
        box-shadow: 0 0 0 2px #a3d2fc !important; /* optional glow */
        border: 1px solid #228be6 !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if "logged_in" not in st.session_state:
    st.session_state.update({
        "logged_in": False,
        "username": None,
        "email": None,
        "user_id": None,
        "oauth_provider": None,
        "show_register": False,
        "messages": [],
        "full_name": None,
        "show_auth": False,
        "temp_user": True,
        "initialized": False,
        "auth_tab": "login",
        "show_quick_prompts": True,
        "uploaded_file": None
    })
if "uploaded_file_list" not in st.session_state:
    st.session_state.uploaded_file_list = []


# --- CONFIGURATION ---


class Config:
    # Azure Storage Configuration
    AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=botstorageai;AccountKey=JLxGrpJew2O1QXFG6HP5nP+oQdu8MtqVc5mC09/Z67Kq2qh+CnyH/4gZK5+6W4CIjw/G105NTAX++AStXmSbbA==;EndpointSuffix=core.windows.net"
    CONTAINER_NAME = "bot-data"
    GOOGLE_LOGO_URL = "https://cdn.shopify.com/s/files/1/0843/6917/8903/files/image.webp?v=1744437922"

    # OAuth Configuration
    GOOGLE_CLIENT_ID = "654156985064-vt48t8gj3qod98m4toivp6975lcdojom.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = "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"
    REDIRECT_URI = "https://shopifyrenderbot.onrender.com/"
    IMAGE_API_URL = "https://ringexpert-backend.azurewebsites.net/generate-image"
    # API Configuration
    CHAT_API_URL = "https://ringexpert-backend.azurewebsites.net/ask"
    BOT_AVATAR_URL = "https://i.imgur.com/JQ6W0nD.png"
    LOGO_URL = "https://ringsandi.com/wp-content/uploads/2023/11/ringsandi-logo.png"
    QUICK_PROMPTS = [
        "What is Ringsandi?",
        "Studio Location?",
        "What will I get different at RINGS & I?",
        "What is the main difference between 14K and 18K gold?",
        "What is the main difference between platinum and gold in terms of purity?"
    ]

# --- AZURE STORAGE SERVICE ---


class AzureStorage:
    def __init__(self):
        self._initialize_storage()

    def _initialize_storage(self):
        """Initialize and validate Azure Storage connection"""
        try:
            logger.info("Initializing Azure Storage connection")
            self.blob_service = BlobServiceClient.from_connection_string(
                Config.AZURE_CONNECTION_STRING)
            self.container = self.blob_service.get_container_client(
                Config.CONTAINER_NAME)

            if not self.container.exists():
                logger.info(f"Creating container: {Config.CONTAINER_NAME}")
                self.container.create_container()
                self._initialize_folder_structure()

            logger.info("Azure Storage initialized successfully")

        except Exception as e:
            logger.error(f"Storage initialization failed: {str(e)}")
            st.error("Failed to initialize storage system. Please contact support.")
            st.stop()

    def _initialize_folder_structure(self):
        """Create required directory structure"""
        try:
            self.upload_blob("users/.placeholder", "")
            self.upload_blob("chats/.placeholder", "")
            logger.info("Created storage folder structure")
        except Exception as e:
            logger.warning(f"Couldn't create folders: {str(e)}")

    def upload_blob(self, blob_name, data):
        """Secure blob upload with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if isinstance(data, (dict, list)):
                data = json.dumps(data, indent=2)
            blob.upload_blob(data, overwrite=True)
            return True
        except Exception as e:
            logger.error(f"Upload failed for {blob_name}: {str(e)}")
            return False

    def upload_file(self, blob_name, file_data, content_type=None):
        """Upload file data to blob storage"""
        try:
            blob = self.container.get_blob_client(blob_name)
            blob.upload_blob(file_data, overwrite=True,
                             content_type=content_type)
            return True
        except Exception as e:
            logger.error(f"File upload failed for {blob_name}: {str(e)}")
            return False

    def download_blob(self, blob_name):
        """Secure blob download with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if blob.exists():
                return blob.download_blob().readall()
            return None
        except Exception as e:
            logger.error(f"Download failed for {blob_name}: {str(e)}")
            return None

    def blob_exists(self, blob_name):
        try:
            return self.container.get_blob_client(blob_name).exists()
        except Exception as e:
            logger.error(f"Existence check failed for {blob_name}: {str(e)}")
            return False

    def user_exists(self, email):
        return self.blob_exists(f"users/{email}.json")

    def create_user(self, email, password=None, username=None, provider=None, **kwargs):
        user_data = {
            "user_id": str(uuid.uuid4()),
            "email": email,
            "username": username or email.split('@')[0],
            "password": self._hash_password(password or "oauth_user"),
            "provider": provider,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            **kwargs
        }

        if self.upload_blob(f"users/{email}.json", user_data):
            return user_data
        return None

    def get_user(self, email):
        data = self.download_blob(f"users/{email}.json")
        return json.loads(data) if data else None

    def authenticate_user(self, email, password):
        user = self.get_user(email)
        if user and self._check_password(password, user["password"]):
            return user
        return None

    def save_chat(self, user_id, messages):
        if messages:  # Only save if there are messages
            return self.upload_blob(f"chats/{user_id}.json", messages)
        return False

    def load_chat(self, user_id):
        data = self.download_blob(f"chats/{user_id}.json")
        return json.loads(data) if data else []

    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _check_password(self, input_password, hashed_password):
        try:
            return bcrypt.checkpw(input_password.encode(), hashed_password.encode())
        except:
            return False


# Initialize storage
storage = AzureStorage()

# image_storage = ImageStorage()
# --- OAUTH SERVICE ---


from authlib.integrations.requests_client import OAuth2Session
import logging

logger = logging.getLogger(__name__)

class OAuthService:
    @staticmethod
    def get_google_auth_url():
        try:
            state = str(uuid.uuid4())
            st.session_state.oauth_state = state
            st.session_state.oauth_timestamp = time.time()

            # Get `redirect` param from the query and save for after login
            query_params = st.query_params
            redirect_url = query_params.get("redirect", "/")
            st.session_state["shopify_return_url"] = redirect_url
            encoded_redirect = urllib.parse.quote(redirect_url)

            client = OAuth2Session(
                client_id=Config.GOOGLE_CLIENT_ID,
                redirect_uri=Config.REDIRECT_URI,
                scope="openid email profile"
            )

            auth_url, _ = client.create_authorization_url(
                "https://accounts.google.com/o/oauth2/v2/auth",
                access_type="offline",
                prompt="consent",
                state=state
            )

            return f"{auth_url}&redirect={encoded_redirect}"

        except Exception as e:
            logger.error(f"Error generating Google Auth URL: {str(e)}")
            return None

    @staticmethod
    def handle_google_callback(code):
        try:
            client = OAuth2Session(
                client_id=Config.GOOGLE_CLIENT_ID,
                redirect_uri=Config.REDIRECT_URI
            )

            token = client.fetch_token(
                "https://oauth2.googleapis.com/token",
                code=code,
                client_secret=Config.GOOGLE_CLIENT_SECRET
            )

            user_info = client.get("https://www.googleapis.com/oauth2/v2/userinfo")
            if user_info.status_code != 200:
                logger.error(f"Failed to get user info: {user_info.text}")
                return None

            return user_info.json()

        except Exception as e:
            logger.error(f"OAuth callback failed: {str(e)}")
            return None



# --- HELPER FUNCTIONS ---


def validate_email(email):
    """Validate email format using regex"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None


def validate_password(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char in "!@#$%^&*()-_=+" for char in password):
        return False, "Password must contain at least one special character"
    return True, ""


def process_uploaded_file(uploaded_file):
    """Process uploaded file and return base64 encoded string"""
    try:
        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            return base64.b64encode(file_bytes).decode('utf-8')
        return None
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return None


def handle_user_prompt(prompt, uploaded_files=None):
    uploaded_files = st.session_state.get("uploaded_file_list", [])
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Show uploaded images in chat
    for file in uploaded_files:
        if file.type.startswith("image/"):
            image_bytes = file.read()
            b64_image = base64.b64encode(image_bytes).decode("utf-8")
            img_html = f'<img src="data:{file.type};base64,{b64_image}" width="150"/>'
            st.session_state.messages.append({"role": "user", "content": img_html})

    # ✅ Handle image generation prompts
    if any(word in prompt.lower() for word in ["generate", "genarate", "create", "show", "give"]) and "image" in prompt.lower():
        try:
            with st.spinner("Generating ring image..."):
                image_resp = requests.post(Config.IMAGE_API_URL, json={"prompt": prompt})
                image_resp.raise_for_status()
                image_url = image_resp.json().get("image_url")
                if image_url:
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": f'<img src="{image_url}" width="300"/>'
                    })
                else:
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": "⚠️ Failed to generate image. No image returned."
                    })
        except Exception as e:
            st.session_state.messages.append({
                "role": "assistant",
                "content": f"⚠️ Error generating image: {e}"
            })
        return  # Exit early, image already handled

    # ✅ Call chatbot backend with the user's prompt
    try:
        with st.spinner("Getting response..."):
            import time
            start_time = time.time()
            resp = requests.post(Config.CHAT_API_URL, json={"question": prompt}, timeout=15)
            resp.raise_for_status()
            duration = time.time() - start_time
            print(f"⏱️ Chat API responded in {duration:.2f} seconds")

            answer = resp.json().get("answer", "Sorry, I didn’t understand that.")

        # Append bot reply
        st.session_state.messages.append({"role": "assistant", "content": answer})

        # Save to storage
        if st.session_state.logged_in:
            storage.save_chat(st.session_state.user_id, st.session_state.messages)

        st.session_state.uploaded_file_list.clear()

    except Exception as e:
        st.session_state.messages.append({
            "role": "assistant",
            "content": f"⚠️ Error getting response: {e}"
        })





def complete_login(user_data):
    st.session_state.update({
        "logged_in": True,
        "user_id": user_data["user_id"],
        "email": user_data["email"],
        "username": user_data["username"],
        "full_name": user_data.get("full_name", user_data["username"]),
        "oauth_provider": user_data.get("provider"),
        "messages": storage.load_chat(user_data["user_id"]) or st.session_state.messages,
        "show_auth": False,
        "temp_user": False,
        "show_quick_prompts": True
    })

    print("✅ Logged in as:", user_data["user_id"])

    # Update last login time
    try:
        user_data["last_login"] = datetime.utcnow().isoformat()
        storage.upload_blob(f"users/{user_data['email']}.json", user_data)
    except Exception as e:
        logger.error(f"Error updating last login: {str(e)}")

    st.query_params["user_id"] = user_data["user_id"]

    # ✅ Shopify return redirect logic (AFTER login)
    redirect_param = st.query_params.get("redirect")
    if redirect_param == "return":
        st.markdown("""
            <script>
              const returnUrl = localStorage.getItem("shopify_return_url");
              if (returnUrl) {
                alert("Thanks for using RingExpert! Returning to your shopping...");
                setTimeout(() => {
                  window.location.href = returnUrl;
                }, 1500);
              }
            </script>
        """, unsafe_allow_html=True)
        return  # ✅ stop here to allow redirect

    # If not returning to Shopify, continue normal flow
    st.rerun()




def logout():
    """Handle logout process"""
    if st.session_state.logged_in and st.session_state.user_id:
        storage.save_chat(st.session_state.user_id, st.session_state.messages)

    # Preserve messages for guest users
    temp_messages = st.session_state.messages if st.session_state.temp_user else []

    st.session_state.update({
        "logged_in": False,
        "user_id": None,
        "email": None,
        "username": None,
        "full_name": None,
        "oauth_provider": None,
        "show_auth": True,  # <-- ✅ Force show login screen after logout
        "temp_user": True,
        "show_quick_prompts": True,
        "uploaded_file": None
    })

    st.session_state.messages = temp_messages
    st.rerun()


# --- AUTHENTICATION UI ---


def show_auth_ui():
    st.markdown("""
        <style>
            .welcome-header {
                text-align: center;
                margin-bottom: 5rem;
            }
            .logo-fixed {
                margin-top: 3px !important;
                padding-top: 0px !important;
            }
            .welcome-container {
                margin-top: 0 !important;
                padding-top: 0px !important;
            }
            .welcome-title {
                font-size: 32px;
                font-weight: 800;
                margin-bottom: 0.75rem;
                color: #000;
                letter-spacing: 0.5px;
                text-transform: uppercase;
            }
            .welcome-subtitle {
                color: #555;
                font-size: 18px;
                font-weight: 400;
                line-height: 1.5;
            }
            .stTextInput>div>div>input {
                border: 1px solid #ddd !important;
                border-radius: 8px !important;
                padding: 12px 16px !important;
                font-size: 15px;
                transition: all 0.3s ease;
            }
            .stTextInput>div>div>input:focus {
                border-color: #000 !important;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1) !important;
                outline: none;
            }
            .stTextInput>label {
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
            }
            .stButton>button {
                border-radius: 8px !important;
                padding: 12px 24px !important;
                font-weight: 600 !important;
                transition: all 0.3s ease !important;
            }
            .stButton>button:not(:disabled):hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="welcome-header">
            <div class="welcome-title">WELCOME TO RINGS & I!</div>
            <div class="welcome-subtitle">The RingExpert is here to help. Ask away!</div>
        </div>
    """, unsafe_allow_html=True)

    tabs = st.tabs(["Sign In", "Create Account"])

    with tabs[0]:
        show_login_form()

    with tabs[1]:
        show_register_form()


def show_login_form():
    """Login form with Forgot Password allowing password reset"""
    if st.session_state.get("show_forgot_password", False):
        st.markdown("### 🔐 Reset Your Password")

        with st.form("forgot_password_form"):
            reset_email = st.text_input("Registered Email", placeholder="you@example.com")
            new_password = st.text_input("New Password", type="password", placeholder="Create a new password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            submit_btn = st.form_submit_button("Update Password", type="primary")

            if submit_btn:
                if not validate_email(reset_email):
                    st.error("Please enter a valid email address")
                elif not storage.user_exists(reset_email):
                    st.error("No account found with that email.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    is_valid, msg = validate_password(new_password)
                    if not is_valid:
                        st.error(msg)
                    else:
                        user_data = storage.get_user(reset_email)
                        user_data["password"] = storage._hash_password(new_password)
                        storage.upload_blob(f"users/{reset_email}.json", user_data)
                        st.success("✅ Password updated successfully! Please log in with your new password.")
                        st.session_state.show_forgot_password = False
                        st.rerun()

        if st.button("← Back to Login"):
            st.session_state.show_forgot_password = False
            st.rerun()

    else:
        with st.form(key="login_form"):
            email = st.text_input("Email Address", key="login_email", placeholder="Enter your email")
            password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")

            col1, col2 = st.columns([2, 1])
            with col2:
                if st.form_submit_button("Forgot Password?", help="Reset your password", type="primary"):
                    st.session_state.show_forgot_password = True
                    st.rerun()

            login_btn = st.form_submit_button("Sign In", type="primary")

            if login_btn:
                if not email or not password:
                    st.error("Please enter both email and password")
                else:
                    user = storage.authenticate_user(email, password)
                    if user:
                        complete_login(user)
                    else:
                        st.error("Invalid credentials. Please try again.")

        # Add Google Sign-In Button
        st.markdown("""
        <style>
            .google-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                background: white;
                color: #757575;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 10px;
                width: 100%;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s;
                margin-top: 10px;
            }
            .google-btn:hover {
                background: #f7f7f7;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .google-logo {
                height: 18px;
                margin-right: 10px;
            }
            .divider {
                display: flex;
                align-items: center;
                margin: 15px 0;
                color: #777;
                font-size: 14px;
            }
            .divider::before, .divider::after {
                content: "";
                flex: 1;
                border-bottom: 1px solid #ddd;
            }
            .divider::before {
                margin-right: 10px;
            }
            .divider::after {
                margin-left: 10px;
            }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<div class="divider">OR</div>', unsafe_allow_html=True)

        google_auth_url = OAuthService.get_google_auth_url()
        st.markdown(f"""
        <a href="{google_auth_url}" target="_self" class="google-btn" style="
            display: flex;
            align-items: center;
            justify-content: center;
            background: white;
            color: #757575;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            width: 100%;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.3s;
            margin-top: 10px;
        ">
            <img src="{Config.GOOGLE_LOGO_URL}" class="google-logo" style="height: 18px; margin-right: 10px;">
            Sign in with Google
        </a>
        """, unsafe_allow_html=True)






def show_register_form():
    """Show only the registration form"""
    with st.form(key="register_form"):
        col1, col2 = st.columns(2)

        with col1:
            first_name = st.text_input("First Name*", help="Required field")
            email = st.text_input(
                "Email Address*", help="We'll use this for account recovery")

        with col2:
            last_name = st.text_input("Last Name")
            username = st.text_input(
                "Username*", help="This will be visible to others")

        password = st.text_input("Password*", type="password",
                                 help="Minimum 8 characters with at least 1 number and 1 special character")
        confirm_password = st.text_input("Confirm Password*", type="password")

        agree = st.checkbox(
            "I agree to the Terms of Service and Privacy Policy*", value=False)

        if st.form_submit_button("Create Account", type="primary"):
            if not all([first_name, email, username, password, confirm_password, agree]):
                st.error("Please fill all required fields (marked with *)")
            elif not validate_email(email):
                st.error("Please enter a valid email address")
            else:
                is_valid, msg = validate_password(password)
                if not is_valid:
                    st.error(msg)
                elif password != confirm_password:
                    st.error("Passwords don't match!")
                elif len(username) < 4:
                    st.error("Username must be at least 4 characters")
                elif " " in username:
                    st.error("Username cannot contain spaces")
                elif storage.user_exists(email):
                    st.error("This email is already registered!")
                else:
                    try:
                        full_name = f"{first_name} {last_name}" if last_name else first_name
                        user_data = storage.create_user(
                            email=email,
                            password=password,
                            username=username,
                            provider="email",
                            first_name=first_name,
                            last_name=last_name,
                            full_name=full_name
                        )

                        if user_data:
                            st.success(
                                "🎉 Account created successfully! Please login with your credentials.")
                            st.session_state.auth_tab = "login"
                            st.rerun()
                        else:
                            st.error(
                                "Failed to create account. Please try again.")
                    except Exception as e:
                        logger.error(f"Registration error: {str(e)}")
                        st.error(
                            "An error occurred during registration. Please try again.")

# --- CHAT UI ---


def show_chat_ui():
    if st.session_state.get("show_auth"):
        show_auth_ui()
        return

    # Sidebar content
    with st.sidebar:
        st.markdown("""
            <div class="logo-container">
                <img src="https://cdn.shopify.com/s/files/1/0843/6917/8903/files/logo_in_black.png?v=1750913006"
                     class="logo-img">
            </div>
        """, unsafe_allow_html=True)

        if not st.session_state.logged_in:
            if st.button("🔍 Explore the details of your ring", key="explore_btn", use_container_width=True):
                st.session_state.show_auth = True
                st.rerun()

        if st.session_state.logged_in:
            st.markdown("""<div style="margin-top: 20px; margin-bottom: 10px;"><strong>🧠 AI RingExpert is ready to help you!</strong></div>""", unsafe_allow_html=True)
            st.markdown("""
                <div style="font-size: 15px; color: #333; font-weight: 500; text-align: center; margin: 10px 0 20px;">
                    Let's help you to determine the following details
                </div>
                <hr style="margin-bottom: 20px;">
            """, unsafe_allow_html=True)

            for emoji, label in [
                ("💎", "Size of Diamonds"),
                ("🔢", "Number of Diamonds on the Ring"),
                ("⚖️", "Quantity of Gold"),
                ("🟡", "Gold Karat")
            ]:
                st.markdown(
                    f"""
                    <div style="
                        width: 100%;
                        padding: 10px 15px;
                        margin: 6px 0;
                        font-size: 13px;
                        font-weight: 600;
                        border: 1px solid #e0e0e0;
                        border-radius: 8px;
                        background-color: #f5f5f5;
                        text-align: left;
                        transition: all 0.2s ease;
                    ">
                        {emoji} {label}
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            for emoji, text in [
                ("💍", "What is Ringsandi?"),
                ("📍", "Studio Location?"),
                ("✨", "What makes RINGS & I different?"),
                ("💰", "14K vs 18K gold - main differences"),
                ("💎", "Platinum vs gold purity comparison")
            ]:
                if st.button(f"{emoji} {text}", key=f"prompt_{text[:10].lower().replace(' ', '_')}",
                             help=f"Ask about {text}", use_container_width=True):
                    handle_user_prompt(text)

        if st.session_state.logged_in:
            st.markdown(f"""
                <div style="text-align: center; margin: 1rem 0 0.5rem; padding: 8px 0; 
                background: #e8f5e9; border-radius: 8px;">
                    <div style="font-weight: 600; color: #000;">
                        {st.session_state.full_name or st.session_state.username}
                    </div>
                    <div style="font-size: 12px; color: #000;">You're logged in</div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("Logout", key="sidebar_logout_btn", type="primary", use_container_width=True):
                logout()
        else:
            st.markdown("""
                <div style="text-align: center; margin: 0.1rem 0 0.1rem; padding: 4px 0;
                background: #f5f5f5; border-radius: 8px;">
                    <div style="font-weight: 600; color: #333;">Guest User</div>
                    <div style="font-size: 12px; color: #777;">History not saved</div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("Login / Sign Up", key="sidebar_login_btn_sidebar", type="primary", use_container_width=True):
                st.session_state.show_auth = True
                st.rerun()

  

    # Main Chat UI CSS + Title
    st.markdown("""
    <style>
        .title-container {
            position: fixed; top: 90px; right: 80px; z-index: 1002;
            background: white; padding: 4px 12px; border-radius: 16px;
        }
        .custom-title {
            font-size: 28px !important; font-weight: 800 !important;
            margin: 0 !important; color: #222; letter-spacing: 0.5px;
        }
        .chat-container { max-width: 800px; margin: 0 auto; padding: 20px 0; }
        .user-message, .bot-message {
            position: relative; padding: 12px 16px; margin-bottom: 12px;
            max-width: 80%; box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .user-message {
            background: #f8f9fa; border-radius: 18px 18px 4px 18px;
            margin-left: auto; border: 1px solid rgba(0,0,0,0.1);
        }
        .bot-message {
            background: white; border-radius: 18px 18px 18px 4px;
            margin-right: auto; border: 1px solid rgba(0,0,0,0.1);
        }
        .file-upload-container {
            position: fixed; 
            bottom: 80px; 
            left: 50%; 
            transform: translateX(-50%); 
            width: 100%; 
            max-width: 800px; 
            padding: 0 20px; 
            z-index: 100;
            display: flex;
            gap: 10px;
        }
        .uploaded-file {
            display: flex; align-items: center; padding: 8px 12px;
            background: #f5f5f5; border-radius: 8px; margin-bottom: 8px;
        }
        .uploaded-file-name { margin-left: 8px; font-size: 14px; }
        .remove-file { margin-left: auto; cursor: pointer; color: #999; }

        .stFileUploader > label { display: none !important; }
        .stFileUploader > button {
            min-width: 40px !important;
            width: 40px !important;
            height: 40px !important;
            padding: 0 !important;
            border-radius: 50% !important;
            background: white !important;
            border: 1px solid #ddd !important;
        }
        .stFileUploader > button:hover {
            background: #f5f5f5 !important;
        }
        .stFileUploader > button > div > p {
            margin: 0 !important;
            font-size: 18px !important;
        }

        @media (max-width: 768px) {
            .title-container {
                right: 5px !important; top: 5px !important;
                padding: 4px 12px !important;
            }
            .custom-title { font-size: 20px !important; }
        }
    </style>
    <div class="title-container">
        <div class="custom-title">AI.RingExpert</div>
    </div>
    <div class="chat-container">
    """, unsafe_allow_html=True)

    # Chat history
    if not st.session_state.get("messages"):
        st.markdown("""<div style="text-align: center; font-size: 24px; font-weight: 600; color: #555; margin-top: 100px;">What can I help with?</div>""", unsafe_allow_html=True)
    else:
        for msg in st.session_state.get("messages", []):
            role_class = "user-message" if msg["role"] == "user" else "bot-message"
            st.markdown(f'<div class="{role_class}">{msg["content"]}</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)  # close .chat-container

    # File upload & input
    st.markdown('<div class="file-upload-container">', unsafe_allow_html=True)

    uploaded_files = None
    if st.session_state.get("logged_in"):
        uploaded_files = st.file_uploader("📎 Upload ring images", key="file_upload", label_visibility="collapsed", accept_multiple_files=True, help="Upload up to 3 files")

        if uploaded_files and st.button("🔍 Analyse Images", key="analyse_image_btn"):
            analyse_images_pipeline(uploaded_files)

    prompt = st.chat_input("Ask...", key="chat_input")
    if prompt:
        handle_user_prompt(prompt, uploaded_files)

    st.markdown('</div>', unsafe_allow_html=True)  # close file-upload-container

    # Footer
    st.markdown("""
    <div class="footer-container" style="position: fixed; bottom: 18px; left: 0; right: 0;
        background: white; padding: 5px 0; text-align: center;
        z-index: 999; width: calc(100% - 16rem); margin-left: 25rem;">
        <div class="footer-content">
            Powered by RINGS & I | <a href="https://ringsandi.com" target="_blank">Visit ringsandi.com!</a>
        </div>
    </div>
    """, unsafe_allow_html=True)


    # --- Gold Result Card ---
    if st.session_state.get('gold_result'):
        gold_result = st.session_state['gold_result']
        # Format total carat weight to 3 decimal places
        diamond_weight_val = gold_result.get('diamond_weight', '-')
        try:
            if diamond_weight_val is not None and diamond_weight_val != '-':
                diamond_weight_val = float(diamond_weight_val)
                diamond_weight_val = f"{diamond_weight_val:.3f}"
        except Exception:
            diamond_weight_val = gold_result.get('diamond_weight', '-')
        st.markdown(f"""
            <div style='
                background: #fff;
                border: 1px solid #e0e0e0;
                border-radius: 14px;
                padding: 32px 28px 20px 28px;
                margin-bottom: 32px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.04);
                max-width: 600px;
                margin-left: auto;
                margin-right: auto;
            '>
                <div style='text-align: center; margin-bottom: 18px;'>
                    <span style='font-size: 1.7rem; font-weight: 700; color: #222; letter-spacing: 0.5px;'>Ring Analysis Summary</span>
                </div>
                <hr style='margin: 10px 0 24px 0; border: none; border-top: 1px solid #e0e0e0;'/>
                <div style='display: flex; flex-wrap: wrap; gap: 0 32px;'>
                    <div style='flex: 1 1 220px;'>
                        <div style='font-size:16px; margin-bottom:10px; color:#222;'><b>Images Processed:</b> {gold_result.get('images_processed', '-')}</div>
                        <div style='font-size:16px; margin-bottom:10px; color:#222;'><b>Total Diamonds:</b> {gold_result.get('total_diamonds', '-')}</div>
                        <div style='font-size:16px; margin-bottom:10px; color:#222;'><b>Total Diamond Carat Weight:</b> {diamond_weight_val}</div>
                    </div>
                    <div style='flex: 1 1 220px;'>
                        <div style='font-size:16px; margin-bottom:10px; color:#222;'><b>Ring Size:</b> {gold_result.get('ring_size', '-')}</div>
                    </div>
                </div>
                <div style='background: #f5f5f5; border-radius:10px; padding: 16px 0 12px 0; margin:24px 0 0 0; text-align:center;'>
                    <span style='font-size:18px; font-weight:700; color:#222;'>18K Gold:</span> <span style='font-size:18px; color:#222; font-weight:500;'>{gold_result.get('gold_18k', '-')} grams</span><br/>
                    <span style='font-size:18px; font-weight:700; color:#222;'>14K Gold:</span> <span style='font-size:18px; color:#222; font-weight:500;'>{gold_result.get('gold_14k', '-')} grams</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
        if st.button("Dismiss Gold Estimate", key="dismiss_gold_card_btn"):
            st.session_state['gold_result'] = None
            st.session_state['show_gold_modal'] = False
            st.rerun()

    

# --- CSS STYLING ---


def load_css():
    import streamlit as st

    # Force light mode override
    st.markdown("""
    <style>
    html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
        background-color: white !important;
        color: black !important;
    }
    [data-testid="stSidebar"] {
        background-color: #f8f9fa !important;
        color: black !important;
    }
    [data-testid="stChatInput"] input {
        background-color: white !important;
        color: black !important;
    }
    @media (prefers-color-scheme: dark) {
        html, body {
            background-color: white !important;
            color: black !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

    # Custom styling for variables, chat, inputs, and layout
    st.markdown("""
    <style>
    :root {
        --primary: #000000;
        --secondary: #FFFFFF;
        --accent: #555555;
        --light: #F9F9F9;
        --dark: #000000;
        --text: #333333;
        --prompt-bg: #F0F0F0;
        --prompt-hover: #E0E0E0;
        --shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }

    input:focus, textarea:focus {
        outline: none !important;
        box-shadow: none !important;
        border: 1px solid #ccc !important;
    }

    [data-testid="stChatInput"] {
        width: 100% !important;
        max-width: 800px !important;
        margin: 0 auto 30px !important;
    }

    [data-testid="stChatInput"] .stTextInput input {
        width: 100% !important;
        border-radius: 32px !important;
        padding: 20px 28px !important;
        font-size: 18px !important;
        min-height: 60px !important;
        background-color: #fff !important;
        box-shadow: none !important;
        outline: none !important;
        background-clip: padding-box !important;
        appearance: none !important;
        transition: all 0.2s ease-in-out;
    }

    [data-testid="stChatInput"] .stTextInput input:focus {
        border: 1px solid #999 !important;
        box-shadow: none !important;
        outline: none !important;
    }

    input:-webkit-autofill {
        box-shadow: 0 0 0 1000px #fff inset !important;
        border-radius: 32px !important;
    }

    section[data-testid="stFileUploader"] label,
    section[data-testid="stFileUploader"] div span {
        display: none !important;
    }

    section[data-testid="stFileUploader"] button {
        width: 40px !important;
        height: 40px !important;
        border-radius: 50% !important;
        border: 1px solid #ccc !important;
        background-color: #fff !important;
        padding: 0 !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        position: relative;
    }

    section[data-testid="stFileUploader"] button::after {
        content: "📎";
        font-size: 20px;
        color: #333;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
    }

    section[data-testid="stFileUploader"] button > div {
        display: none !important;
    }

    .user-message, .bot-message {
        padding: 12px 16px !important;
        max-width: 80% !important;
        border: 1px solid rgba(0,0,0,0.1) !important;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1) !important;
        margin-bottom: 12px !important;
        animation: fadeIn 0.3s ease-out;
    }

    .user-message {
        background-color: #f8f9fa !important;
        border-radius: 18px 18px 4px 18px !important;
        margin-left: auto !important;
    }

    .bot-message {
        background-color: white !important;
        border-radius: 18px 18px 18px 4px !important;
        margin-right: auto !important;
        position: relative;
    }

    [data-testid="stSidebar"] {
        background-color: var(--light) !important;
        border-right: 1px solid rgba(0, 0, 0, 0.1);
    }

    .stButton button[kind="secondary"] {
        background-color: var(--prompt-bg);
        color: var(--dark);
        border: 1px solid rgba(0, 0, 0, 0.1);
        border-radius: 10px;
        padding: 6px 10px !important;
        margin: 4px 0;
        font-size: 12px;
        font-weight: 600;
        width: 100%;
        text-align: left;
    }

    .stButton button[kind="secondary"]:hover {
        background-color: var(--prompt-hover);
        transform: translateX(4px);
        box-shadow: 1px 1px 4px rgba(0, 0, 0, 0.08);
    }

    .stButton button[kind="primary"] {
        background-color: var(--primary);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
    }

    @media (max-width: 768px) {
        .user-message, .bot-message {
            max-width: 90% !important;
        }

        .bot-message::before {
            left: -30px !important;
        }
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    input:focus {
        outline: none !important;
        box-shadow: none !important;
        border: 1px solid #ccc !important;
    }

    [data-testid="stChatInput"] .stTextInput input {
        border: 1px solid #ccc !important;
        border-radius: 32px !important;
        padding: 20px 28px !important;
        font-size: 18px !important;
        min-height: 60px !important;
        background-color: #fff !important;
        box-shadow: none !important;
        outline: none !important;
    }

    [data-testid="stChatInput"] .stTextInput input:focus {
        border: 1px solid #999 !important;
        box-shadow: none !important;
        outline: none !important;
    }
                def load_css():
    # ... (keep your existing CSS) ...

   
        /* Restore the collapse button */
        [data-testid="collapsedControl"] {
            display: flex !important;
            left: 18px !important;
            top: 18px !important;
        }

        /* Fix conflicting visibility rules */
        #MainMenu {visibility: visible !important;}
        header {visibility: visible !important;}

        /* Ensure sidebar doesn't hide the button */
        [data-testid="stSidebar"] > div:first-child {
            padding-top: 2rem !important;
        }
   
    </style>
    """, unsafe_allow_html=True)



# --- OAUTH CALLBACK HANDLER ---
def handle_oauth_callback():
    query_params = st.query_params
    code = query_params.get("code")
    state = query_params.get("state")
    error = query_params.get("error")

    if error:
        st.error(f"OAuth error: {error}")
        return

    if code and state == st.session_state.get("oauth_state"):  # Validate state matches
        try:
            user_info = OAuthService.handle_google_callback(code)
            if user_info:
                email = user_info.get("email")
                if email:
                    # ✅ Clear query params
                    st.query_params.clear()

                    user = storage.get_user(email)
                    if not user:
                        user = storage.create_user(
                            email=email,
                            provider="google",
                            username=email.split('@')[0],
                            full_name=user_info.get("name", ""),
                            first_name=user_info.get("given_name", ""),
                            last_name=user_info.get("family_name", "")
                        )

                    if user:
                        # ✅ Reset session and login
                        st.session_state.clear()
                        complete_login(user)

                        # ✅ Inject JavaScript redirect (reads from localStorage)
                        st.markdown("""
                            <script>
                                const returnUrl = localStorage.getItem("shopify_return_url");
                                if (returnUrl) {
                                    setTimeout(() => {
                                        window.location.href = returnUrl;
                                    }, 800);
                                }
                            </script>
                        """, unsafe_allow_html=True)
                        return

        except Exception as e:
            st.error(f"Authentication failed: {str(e)}")
            logger.error(f"OAuth callback error: {str(e)}")



def load_responsive_css():
    import streamlit as st
    st.markdown("""
    <style>
    /* ------------------------------
       Root Font Scaling for Mobile
    ------------------------------ */
    :root {
        font-size: 16px;
    }

    @media (max-width: 768px) {
        :root {
            font-size: 14px;
        }
    }

    @media (max-width: 480px) {
        :root {
            font-size: 13px;
        }
    }

    /* ------------------------------
       Chat Input
    ------------------------------ */
      [data-testid="stChatInput"] .stTextInput input {
    border-radius: 32px !important;
    padding: 20px 30px !important;
    
    font-size: 1rem !important;
    min-height: 60px !important;
    background-color: #fff !important;
    box-shadow: none !important;
    outline: none !important;
    }


    @media (max-width: 480px) {
        [data-testid="stChatInput"] .stTextInput input {
            font-size: 0.875rem !important;
            padding: 16px 20px !important;
        }
    }

    /* ------------------------------
       Chat Bubbles
    ------------------------------ */
    .user-message, .bot-message {
        padding: 12px 16px !important;
        font-size: 1rem;
        border: 1px solid rgba(0,0,0,0.1) !important;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1) !important;
        margin-bottom: 12px !important;
    }

    .user-message {
        background-color: #f8f9fa !important;
        border-radius: 18px 18px 4px 18px !important;
        margin-left: auto !important;
    }

    .bot-message {
        background-color: white !important;
        border-radius: 18px 18px 18px 4px !important;
        margin-right: auto !important;
        position: relative;
    }

    @media (max-width: 768px) {
        .user-message, .bot-message {
            max-width: 95% !important;
            font-size: 0.875rem;
        }

        .bot-message::before {
            left: -28px !important;
        }
    }

    /* ------------------------------
       Sidebar - Non-Scrollable Fit
    ------------------------------ */
   
    section[data-testid="stSidebar"] > div {
        display: flex !important;
        flex-direction: column !important;
        justify-content: flex-start !important;
        gap: 6px !important;
        padding: 10px !important;
    }

    .prompt-btn {
        padding: 6px 10px !important;
        font-size: 0.75rem !important;
        margin: 3px 0 !important;
    }

    .stButton button {
        padding: 6px 10px !important;
        font-size: 0.75rem !important;
    }

    .logo-container {
        padding: 4px 0 !important;
    }

    .logo-img {
        max-width: 55px !important;
        height: auto !important;
        margin: 0 auto 6px auto !important;
        display: block;
    }

    /* ------------------------------
       Footer Responsiveness
    ------------------------------ */
    .footer-container {
        position: fixed;
        bottom: 10px;
        left: 0;
        right: 0;
        background: white;
        padding: 10px 10px;
        text-align: center;
        z-index: 999;
        width: 100% !important;
        font-size: 0.85rem;
    }

    @media (max-width: 768px) {
        .footer-container {
            font-size: 0.75rem;
            padding: 8px 8px !important;
        }
    }

    /* ------------------------------
       File Upload Icon
    ------------------------------ */
    section[data-testid="stFileUploader"] button {
        width: 40px !important;
        height: 40px !important;
        border-radius: 50% !important;
        border: 1px solid #ccc !important;
        background-color: #fff !important;
        padding: 0 !important;
        position: relative;
    }

    section[data-testid="stFileUploader"] button::after {
        content: "📎";
        font-size: 20px;
        color: #333;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
    }
  
/* GLOBAL override to kill extra square border */
input:focus {
    outline: none !important;
    box-shadow: none !important;
    border: 1px solid #ccc !important;
}

/* Force override on stChatInput input again */
[data-testid="stChatInput"] .stTextInput input {
    border: 1px solid #ccc !important;
    border-radius: 32px !important;
    padding: 20px 28px !important;
    font-size: 18px !important;
    min-height: 60px !important;
    background-color: #fff !important;
    box-shadow: none !important;
    outline: none !important;
}

/* Focus override (when clicked) */
[data-testid="stChatInput"] .stTextInput input:focus {
    border: 1px solid #999 !important;
    box-shadow: none !important;
    outline: none !important;
}


    </style>
    """, unsafe_allow_html=True)


# --- IMAGE ANALYSIS PIPELINE ---
def analyse_images_pipeline(uploaded_files):
    import streamlit as st
    import base64

    if not uploaded_files:
        st.warning("⚠️ Please upload at least one image.")
        return

    # ✅ Add this block to ensure user_id is present
    user_id = st.session_state.get("user_id")

    if not user_id:
        st.error("❌ Please log in first. Cannot upload without user ID.")
        return
    else:
        st.success(f"🔐 Uploading as user ID: {user_id}")

    # Continue with rest of your upload logic...
    images_b64 = []
    user_id = str(st.session_state.user_id)

    for file in uploaded_files:
        try:
            file_bytes = file.getvalue()
            filename = f"{uuid.uuid4()}_{file.name}"
            
            # Upload image
            upload_success = image_storage.upload_user_image(user_id, file_bytes, filename)
            
            if not upload_success:
                continue  # Skip to next file if upload failed
                
            # Convert to base64 for API processing
            b64 = base64.b64encode(file_bytes).decode('utf-8')
            images_b64.append(b64)
            
        except Exception as e:
            st.error(f"Error processing {file.name}: {str(e)}")
            continue

    # Proceed to API call or whatever logic follows here

    # Proceed with API logic (unchanged)
    # 1. Call first API to get diamond count
    api1_url = "https://diamond-count-analysis.centralindia.inference.ml.azure.com/score"
    api1_token = "AIk6eqLSWKnvD6mBhtLNcOQycfbUtrKXh9tzWqXbgldE5MADQavLJQQJ99BFAAAAAAAAAAAAINFRAZML4Tbb"
    headers1 = {"Authorization": f"Bearer {api1_token}"}
    body1 = {"images": images_b64}

    try:
        with st.spinner("Analysing image for diamond count..."):
            resp1 = requests.post(api1_url, json=body1, headers=headers1, timeout=60)
            resp1.raise_for_status()
            diamond_count = resp1.json().get("prediction")
            if diamond_count is None:
                st.error("First API did not return a diamond count.")
                return
            st.success(f"Number of diamonds detected: {diamond_count}")
    except Exception as e:
        st.error(f"Error in first analysis API: {e}")
        return

    # 🔁 Remaining logic for second and third API (unchanged in your file)

    # 2. Call second API with images and diamond count
    api2_url = "https://diamond-count-analysis-xdahy.centralindia.inference.ml.azure.com/score"
    api2_token = "FCcJeeKvQNBjjw8mN78So94pafwIfP9mdfamDy3B7yoKiEfURx0EJQQJ99BFAAAAAAAAAAAAINFRAZML2MOQ"
    headers2 = {"Authorization": f"Bearer {api2_token}"}
    body2 = {"images": images_b64, "num_diamonds": diamond_count}
    try:
        with st.spinner("Running second analysis with diamond count..."):
            resp2 = requests.post(api2_url, json=body2,
                                  headers=headers2, timeout=60)
            resp2.raise_for_status()
            import json
            result2 = resp2.json()
            if isinstance(result2, str):
                try:
                    result2 = json.loads(result2)
                except Exception:
                    st.error(
                        "Second API returned a string that could not be parsed as JSON.")
                    st.write("Raw response:", result2)
                    return
            prediction = result2.get("prediction", {})
            total_carat_weight = prediction.get("total_carat_weight")
            num_diamonds = prediction.get("num_diamonds") or prediction.get(
                "num_diamonds", diamond_count)
            if total_carat_weight is not None:
                st.success(f"Total Carat Weight: {total_carat_weight}")
            else:
                st.warning(
                    "Could not extract total carat weight from the response.")

            # --- Third API Call ---
            # Prepare data for third API
            ring_id = "test_ring_001"  # Placeholder, can be dynamic
            total_diamonds = num_diamonds if num_diamonds is not None else diamond_count
            diamond_weight = total_carat_weight
            ring_size = 12.0  # Placeholder, can be dynamic
            diamond_weight_available = 1.0  # Placeholder
            ring_size_available = 1.0  # Placeholder
            images = images_b64
            if total_diamonds is None or diamond_weight is None:
                st.warning(
                    "Cannot call third API: missing diamond count or carat weight.")
                return
            api3_url = "https://gold-weight-endpoint.centralindia.inference.ml.azure.com/score"
            api3_token = "03oU2hS62pbblSnXemnmMtIb2RJW3iJkWvCfapzO3OLQfEltP0tlJQQJ99BFAAAAAAAAAAAAINFRAZML4ML3"
            headers3 = {"Content-Type": "application/json"}
            if api3_token:
                headers3["Authorization"] = f"Bearer {api3_token}"
            body3 = {
                "ring_id": ring_id,
                "total_diamonds": total_diamonds,
                "diamond_weight": diamond_weight,
                "ring_size": ring_size,
                "diamond_weight_available": diamond_weight_available,
                "ring_size_available": ring_size_available,
                "images": images
            }
            try:
                with st.spinner("Estimating gold weights (third analysis)..."):
                    resp3 = requests.post(
                        api3_url, json=body3, headers=headers3, timeout=60)
                    resp3.raise_for_status()
                    result3 = resp3.json()
                    if isinstance(result3, str):
                        try:
                            result3 = json.loads(result3)
                        except Exception:
                            st.error(
                                "Third API returned a string that could not be parsed as JSON.")
                            st.write("Raw response:", result3)
                            return
                    gold_18k = result3.get("gold_18k")
                    gold_14k = result3.get("gold_14k")
                    ring_id = result3.get("ring_id")
                    images_processed = result3.get("images_processed")
                    # Store all relevant info for the card
                    st.session_state['gold_result'] = {
                        'gold_18k': gold_18k,
                        'gold_14k': gold_14k,
                        'ring_id': ring_id,
                        'images_processed': images_processed,
                        'total_diamonds': total_diamonds,
                        'diamond_weight': diamond_weight,
                        'ring_size': ring_size,
                        'diamond_weight_available': diamond_weight_available,
                        'ring_size_available': ring_size_available
                    }
                    st.session_state['show_gold_modal'] = False
                    st.rerun()
            except Exception as e:
                st.error(f"Error in third analysis API: {e}")
                return
    except Exception as e:
        st.error(f"Error in second analysis API: {e}")
        return

# --- MAIN APP FLOW ---
def restore_user_id_from_url():
    query_params = st.query_params  # Updated to new API
    user_id = query_params.get("user_id")
    if user_id and not st.session_state.get("user_id"):
        st.session_state["user_id"] = user_id
        st.session_state["logged_in"] = True  # assume logged in
        print("🔁 Restored user_id from URL:", user_id)



def main():
    query_params = st.query_params

    if "code" in query_params and "state" in query_params:
        handle_oauth_callback()
        return

    restore_user_id_from_url()
    threading.Thread(target=warm_up_bot).start()
    load_css()
    load_responsive_css()

    show_chat_ui()  # ✅ Only show UI if not coming from OAuth

if __name__ == "__main__":
    main()
