from azure.storage.blob import BlobServiceClient
from config import Config
import streamlit as st

class ImageStorage:
    def __init__(self):
        try:
            # Use connection string from Config
            self.blob_service_client = BlobServiceClient.from_connection_string(
                Config.AZURE_CONNECTION_STRING
            )
            self.container_name = "imagedata"
            self.container_client = self.blob_service_client.get_container_client(self.container_name)
            self._ensure_container_exists()
        except Exception as e:
            st.error(f"Failed to initialize image storage: {str(e)}")
            raise

    def _ensure_container_exists(self):
        """Ensure the container exists, create if it doesn't"""
        try:
            if not self.container_client.exists():
                self.container_client.create_container()
                st.success(f"Created container: {self.container_name}")
        except Exception as e:
            st.error(f"Container check/creation failed: {str(e)}")
            raise

    def upload_user_image(self, user_id, image_bytes, filename):
        """Upload image to Azure Blob Storage"""
        try:
            blob_path = f"{user_id}/{filename}"
            
            # Show upload status in UI
            with st.spinner(f"Uploading {filename}..."):
                self.container_client.upload_blob(
                    name=blob_path,
                    data=image_bytes,
                    overwrite=True
                )
            
            st.success(f"Successfully uploaded: {filename}")
            print(f"✅ Uploaded to Azure: {blob_path}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to upload {filename}: {str(e)}"
            st.error(error_msg)
            print(f"❌ {error_msg}")
            return False
