from dotenv import load_dotenv
import os

load_dotenv()

ACCOUNT_ID = os.getenv('ACCOUNT_ID')
API_KEY = os.getenv('API_KEY')
API_ENDPOINT = os.getenv('API_ENDPOINT')