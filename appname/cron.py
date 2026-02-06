from .models import Notifications,Log,HatirlatmaTarihleri
from django.core.mail import get_connection,send_mail

# example bıldırım
from django.conf import settings
from django.utils import timezone
import requests
import re

# 🔹 Mail body builder (aynı dosya, class dışı)
def build_reminder_email(hatirlatma_turu_cap, message, year):
    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background-color:#F4F7FB;">
        <table width="100%" cellpadding="0" cellspacing="0" style="padding:30px 0;">
            <tr>
                <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0"
                        style="background:#FFFFFF;border-radius:12px;
                        box-shadow:0 8px 24px rgba(0,0,0,0.06);overflow:hidden;">

                        <tr>
                            <td style="
                                background:linear-gradient(135deg,#1D64F2,#3B82F6);
                                padding:20px;
                                text-align:center;
                                font-family:Arial,sans-serif;
                            ">
                                <h1 style="
                                    margin:0;
                                    color:#FFFFFF;
                                    font-size:18px;
                                    font-weight:600;
                                ">
                                    Aklımda
                                </h1>
                            </td>
                        </tr>

                        <tr>
                            <td style="padding:28px;font-family:Arial,sans-serif;">
                                <h2 style="color:#1D64F2;">
                                    Araç {hatirlatma_turu_cap} Hatırlatması
                                </h2>

                                <p>Merhaba 👋</p>

                                <div style="
                                    background:#F1F5FF;
                                    border-left:4px solid #1D64F2;
                                    padding:16px;
                                    border-radius:8px;
                                    margin:16px 0;">
                                    {message}
                                </div>

                                <p>
                                    Güvenli sürüşler dileriz 🚗<br>
                                    <b>Aklımda Destek Ekibi</b>
                                </p>
                            </td>
                        </tr>

                        <tr>
                            <td style="background:#F9FAFB;padding:14px;
                            text-align:center;font-size:12px;color:#9CA3AF;">
                                © {year} Aklımda
                            </td>
                        </tr>

                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


def send_reminder_mail(user, subject, html_body, connection):
    if not user.email:
        return False

    try:
        send_mail(
            subject=subject,
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_body,
            connection=connection
        )
        return True
    except Exception:
        return False


def create_notification(hatirlatma_tarihi):
    try:
        Notifications.objects.create(
            hatirlatma_tarihleri=hatirlatma_tarihi
        )
        return True
    except Exception:
        return False


def normalize_phone(phone: str) -> str:
    """
    +, boşluk, -, () vs temizler
    Sadece rakam bırakır
    """

    if not phone:
        return None

    return re.sub(r"\D", "", phone)



def send_sms_reminder(user,message_sms):
    if not user.phone_number:
        return False

    url = "https://smsgw.mutlucell.com/smsgw-ws/sndblkex"

    phone = normalize_phone(user.phone_number)

    xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
                        <smspack ka="gokhan3467" pwd="{settings.API_KEY}" org="908505545406" charset="turkish">

                            <mesaj>
                                <metin>{message_sms}</metin>
                                <nums>{phone}</nums>
                            </mesaj>

                        </smspack>
                        """

    headers = {
        "Content-Type": "text/xml; charset=UTF-8"
    }

    try:

        sms_response = requests.post(
            url,
            data=xml_data.encode("utf-8"),
            headers=headers,
            timeout=15
        )

        code = sms_response.text.strip()


        # HTTP hata
        if sms_response.status_code != 200:
            return False


        # Başarılı (ID dönmüş)
        elif code.startswith("$") and "#" in code:
            return True


        # API hata kodu
        else:
            return False
    except Exception:
        return False





def notifications_push():
    connection = None
    fatal_error = None

    response = {
        'mail_successful': 0,
        'mail_unsuccessful': 0,
        'notification_successful': 0,
        'notification_unsuccessful': 0,
        'sms_successful': 0,
        'sms_unsuccessful': 0,
    }

    mail_error_happened = False
    sms_error_happened = False
    notif_error_happened = False

    try:
        bugun = timezone.now().date()

        hatirlatma_tarihleri = HatirlatmaTarihleri.objects.select_related(
            'hatirlatici__arac__user'
        ).filter(
            is_stopped=False,
            tarih=bugun,
            hatirlatici__is_removed=False,
        )

        gonderilmis_ids = set(
            Notifications.objects.filter(
                hatirlatma_tarihleri__in=hatirlatma_tarihleri
            ).values_list('hatirlatma_tarihleri_id', flat=True)
        )

        connection = get_connection()
        connection.open()

        for data in hatirlatma_tarihleri:
            if data.id in gonderilmis_ids:
                continue

            user = data.hatirlatici.arac.user
            hatirlatma_turu = data.hatirlatici.hatirlatma_turu
            hatirlatma_turu_cap = hatirlatma_turu.capitalize()
            arac_plakasi = data.hatirlatici.arac.arac_plakasi

            message = (
                f"{arac_plakasi} plakalı aracınız için "
                f"{hatirlatma_turu} ile ilgili gerekli kontrolleri yapmayı unutmayın."
            )

            message_sms = (
                f"{arac_plakasi} plakalı aracınız için "
                f"{hatirlatma_turu} ile ilgili gerekli kontrolleri yapmayı unutmayın. "
                f"Aklımda"
            )

            email_body = build_reminder_email(
                hatirlatma_turu_cap,
                message,
                timezone.now().year
            )

            # 🔹 MAIL
            mail_ok = send_reminder_mail(
                user=user,
                subject=f"Araç {hatirlatma_turu_cap} Hatırlatması",
                html_body=email_body,
                connection=connection
            )

            if mail_ok:
                response['mail_successful'] += 1
            else:
                response['mail_unsuccessful'] += 1
                mail_error_happened = True


            sms_ok = send_sms_reminder(user,message_sms)

            if sms_ok:
                response['sms_successful'] += 1
            else:
                response['sms_unsuccessful'] += 1
                sms_error_happened = True

            # 🔹 NOTIFICATION
            notif_ok = create_notification(data)

            if notif_ok:
                response['notification_successful'] += 1
            else:
                response['notification_unsuccessful'] += 1
                notif_error_happened = True

    except Exception as e:
        fatal_error = str(e)

    finally:
        if connection:
            connection.close()

        Log.objects.create(
            explanation=(
                f"Tarih:{timezone.now().strftime('%Y-%m-%d')} | "
                f"Mail OK:{response['mail_successful']} "
                f"Mail FAIL:{response['mail_unsuccessful']} "
                f"Sms OK:{response['sms_successful']} "
                f"Sms FAIL:{response['sms_unsuccessful']} "
                f"Notif OK:{response['notification_successful']} "
                f"Notif FAIL:{response['notification_unsuccessful']} | "
                f"MailError:{mail_error_happened} "
                f"NotifError:{notif_error_happened} "
                f"SmsError:{sms_error_happened} "
                f"FatalError:{bool(fatal_error)}"
            )
        )





