import logging
from authlib.integrations.requests_client import OAuth2Session
from config import Config  # Make sure Config is correctly loading the credentials

logger = logging.getLogger(__name__)

class OAuthService:

    @staticmethod
    def get_google_auth_url():
        try:
            client = OAuth2Session(
                client_id=Config.GOOGLE_CLIENT_ID,
                redirect_uri=Config.REDIRECT_URI
            )

            auth_url, _ = client.create_authorization_url(
                "https://accounts.google.com/o/oauth2/v2/auth",
                scope="openid email profile",
                access_type="offline",
                prompt="consent",
                state="google"  # Optional: consider generating random state for security
            )

            return auth_url

        except Exception as e:
            logger.error(f"[OAuthService] Error generating Google Auth URL: {str(e)}")
            return None

    @staticmethod
    def handle_google_callback(code):
        try:
            client = OAuth2Session(
                client_id=Config.GOOGLE_CLIENT_ID,
                redirect_uri=Config.REDIRECT_URI
            )

            token = client.fetch_token(
                url="https://oauth2.googleapis.com/token",
                code=code,
                client_secret=Config.GOOGLE_CLIENT_SECRET
            )

            user_info_response = client.get("https://www.googleapis.com/oauth2/v3/userinfo")

            if user_info_response.status_code != 200:
                logger.error(f"[OAuthService] Failed to fetch user info: {user_info_response.text}")
                return None

            return user_info_response.json()

        except Exception as e:
            logger.error(f"[OAuthService] OAuth callback failed: {str(e)}")
            return None
