from django.contrib.auth import get_user_model
from django.utils import timezone

from . import settings
from .models import MagicLink
from .utils import get_client_ip

User = get_user_model()


class MagicLinkBackend():

    def authenticate(self, request, token=None, email=None):
        if settings.VERIFY_INCLUDE_EMAIL and not email:
            return

        if settings.EMAIL_IGNORE_CASE:
            email = email.lower()

        magiclinks = MagicLink.objects.filter(token=token, disabled=False)
        if email:
            magiclinks = magiclinks.filter(email=email)
        if not magiclinks:
            return

        magiclink = MagicLink.objects.get(token=token)

        if timezone.now() > magiclink.expiry:
            magiclink.disable()
            return

        if settings.REQUIRE_SAME_IP:
            if magiclink.ip_address != get_client_ip(request):
                magiclink.disable()
                return

        if settings.REQUIRE_SAME_BROWSER:
            if magiclink.cookie_value != request.COOKIES.get('magiclink'):
                magiclink.disable()
                return

        if magiclink.times_used >= settings.TOKEN_USES:
            magiclink.disable()
            return

        user = User.objects.get(email=magiclink.email)

        if not settings.ALLOW_SUPERUSER_LOGIN and user.is_superuser:
            magiclink.disable()
            return

        if not settings.ALLOW_STAFF_LOGIN and user.is_staff:
            magiclink.disable()
            return

        magiclink.used()

        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return
