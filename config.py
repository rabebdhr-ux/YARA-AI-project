from dotenv import load_dotenv
import os

load_dotenv()

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
NVIDIA_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"