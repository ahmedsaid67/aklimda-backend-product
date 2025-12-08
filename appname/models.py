from django.db import models

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

from rest_framework.authtoken.models import Token



class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    credit = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    player_id = models.CharField(max_length=200, null=True, blank=True)


    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


    def __str__(self):
        return self.email



class PasswordResetCode(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(minutes=15))

    def is_valid(self):
        return timezone.now() < self.expires_at



# tokwn model

import binascii
import os
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class SessionToken(models.Model):
    key = models.CharField(_("Key"), max_length=40, primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='session_tokens', on_delete=models.CASCADE, verbose_name=_("User")
    )
    created = models.DateTimeField(_("Created"), auto_now_add=True)

    class Meta:
        verbose_name = _("Session Token")
        verbose_name_plural = _("Session Tokens")

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key



# bize ulaşın web


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()

# bize ulaşın mobil

class Iletisim(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='contact_user')
    message = models.TextField()



#güncel paylaşımlar

class CurrentPosts(models.Model):
    title = models.CharField(max_length=256)
    explanations = models.TextField()
    image = models.ImageField(
        upload_to='current_posts/',
        null=True,
        blank=True
    )
    is_removed = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.title


# araclar

class Araclar(models.Model):
    user = models.ForeignKey(CustomUser,on_delete=models.CASCADE, related_name='arac_user')
    arac_markasi = models.CharField(max_length=256)
    arac_modeli = models.CharField(max_length=256)
    arac_no = models.CharField(max_length=600,null=True,blank=True)
    arac_plakasi = models.CharField(max_length=256)
    is_removed = models.BooleanField(default=False)


    def save(self, *args, **kwargs):
        # Yeni kayıt oluşturuluyorsa
        if not self.pk:
            count = Araclar.objects.filter(user=self.user).count() + 1
            self.arac_no = f"{count:04d} {self.arac_markasi} {self.arac_modeli}"
        else:
            # Güncelleme: marka veya model değiştiyse arac_no güncelle
            old = Araclar.objects.get(pk=self.pk)
            if old.arac_markasi != self.arac_markasi or old.arac_modeli != self.arac_modeli:
                # Mevcut numaranın başındaki sayıyı al
                count_part = self.arac_no.split(' ')[0]
                self.arac_no = f"{count_part} {self.arac_markasi} {self.arac_modeli}"
        super().save(*args, **kwargs)


# hatırlatıcılar

from datetime import time



HATIRLATMA_TURU = [
    ('muayene', 'Muayene'),
    ('vergi', 'Vergi'),
    ('sigorta', 'Sigorta'),
]
class Hatirlaticilar(models.Model):
    arac = models.ForeignKey(Araclar, on_delete=models.CASCADE, related_name='hatirlatma_arac')
    hatirlatma_turu = models.CharField(max_length=20, choices=HATIRLATMA_TURU)
    son_tarih = models.DateField()
    is_removed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.arac.arac_no} - {self.get_hatirlatma_turu_display()}"


class HatirlatmaTarihleri(models.Model):
    hatirlatici = models.ForeignKey(Hatirlaticilar, on_delete=models.CASCADE, related_name='hatirlatma_tarihleri')
    tarih = models.DateField()
    saat = models.TimeField(default=time(12, 0))
    is_stopped = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.tarih} - {self.saat}"


# bildirimler

class Notifications(models.Model):
    hatirlatma_tarihleri = models.OneToOneField(HatirlatmaTarihleri, on_delete=models.CASCADE, related_name='notifcation')
    explanation = models.TextField()

    def save(self, *args, **kwargs):
        if not self.explanation:
            ht = self.hatirlatma_tarihleri
            hatirlatici = ht.hatirlatici

            tur = hatirlatici.get_hatirlatma_turu_display()
            tarih = ht.tarih.strftime("%d.%m.%Y")

            arac = hatirlatici.arac
            plaka = arac.arac_plakasi
            arac_no = arac.arac_no

            self.explanation = (
                f"{plaka} plakalı ({arac_no}) aracınız için tanımladığınız "
                f"{tur} hatırlatıcısının {tarih} tarihli bildirimi tarafınıza "
                f"iletilmiştir. Lütfen ilgili işlemleri zamanında tamamlamayı unutmayın."
            )

        super().save(*args, **kwargs)




