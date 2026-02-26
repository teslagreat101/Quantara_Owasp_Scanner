import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
from dotenv import load_dotenv

load_dotenv()

def initialize_firebase():
    """Initialize Firebase Admin SDK."""
    if not firebase_admin._apps:
        # If we have a service account JSON, use it
        service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")
        if service_account_path and os.path.exists(service_account_path):
            cred = credentials.Certificate(service_account_path)
            firebase_admin.initialize_app(cred)
        else:
            # Fallback to default project ID from env
            project_id = os.getenv("NEXT_PUBLIC_FIREBASE_PROJECT_ID")
            firebase_admin.initialize_app(options={'projectId': project_id})
    
    return firestore.client()

# Initialize and export db
db = initialize_firebase()
