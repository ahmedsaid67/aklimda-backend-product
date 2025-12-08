from rest_framework.authentication import TokenAuthentication
from .models import SessionToken

class MultiTokenAuthentication(TokenAuthentication):
    model = SessionToken