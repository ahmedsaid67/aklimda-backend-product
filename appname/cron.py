from .models import Hatirlaticilar, HatirlatmaTarihleri, Notifications
from django.contrib.auth import get_user_model
User = get_user_model()
from django.utils import timezone
from django.conf import settings
import requests
import logging

logger = logging.getLogger(__name__)

PUSHY_API_KEY = settings.PUSHY_API_KEY

def notifications_push():
    bugun = timezone.now().date()

    hatirlatma_tarihleri = HatirlatmaTarihleri.objects.filter(
        is_stopped=False,
        hatirlatici__is_removed=False,
        tarih=bugun
    )

    logger.info(f"[CRON] {hatirlatma_tarihleri.count()} adet hatırlatma bulundu. Tarih = {bugun}")

    for data in hatirlatma_tarihleri:
        try:
            user = data.hatirlatici.arac.user
            token = user.player_id

            if not token:
                logger.warning(f"[CRON] Kullanıcı token yok: user_id={user.id}")
                continue

            hatirlatma_turu = data.hatirlatici.hatirlatma_turu
            hatirlatma_turu_cap = hatirlatma_turu.capitalize()
            arac_plakasi = data.hatirlatici.arac.arac_plakasi

            # Notifications objesi oluştur
            Notifications.objects.create(hatirlatma_tarihleri=data)

            # Pushy payload
            payload = {
                "to": token,
                "data": {
                    "title": f"{hatirlatma_turu_cap} Hatırlatması",
                    "message": f"{arac_plakasi} plakalı aracınız için {hatirlatma_turu} ile ilgili gerekli kontrolleri yapmayı unutmayın."
                }
            }

            # API isteği
            response = requests.post(
                f"https://api.pushy.me/push?api_key={PUSHY_API_KEY}",
                json=payload,
                timeout=15
            )

            if response.status_code == 200:
                logger.info(f"[CRON] Bildirim gönderildi → user_id={user.id}, token={token}")
            else:
                logger.error(f"[CRON] Pushy hata → status={response.status_code}, response={response.text}")

        except Exception as e:
            logger.exception(f"[CRON] HATA! Hatırlatma gönderilirken sorun oldu. ID={data.id}")



