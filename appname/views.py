from django.db.models import Prefetch

from django.shortcuts import render
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.views import APIView
from .serializers import CustomUserSerializer,CustomAuthTokenSerializer
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from django.contrib.auth import get_user_model
from .models import SessionToken,Hatirlaticilar
User = get_user_model()

# Your existing views remain unchanged
class CustomAuthToken(ObtainAuthToken):
    serializer_class = CustomAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        token = SessionToken.objects.create(user=user)
        # Kullanıcı bilgilerini serialize ederek döndürelim
        user_data = CustomUserSerializer(user).data

        return Response({
            'token': token.key,
            'user': user_data
        })



class CheckToken(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': 'Token is valid'})

class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.auth
        if token:
            token.delete()
            return Response({"message": "Logged out from current session"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class Register(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token = SessionToken.objects.create(user=user)

        return Response({
            'token': token.key,
            'user': serializer.data  # serializer zaten user'a bağlı
        }, status=status.HTTP_201_CREATED)


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserDelete(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')


        if not email or not password:
            return Response({'error': 'Email ve şifre gereklidir.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Bu e-posta ile kayıtlı bir kullanıcı bulunamadı.'},
                            status=status.HTTP_404_NOT_FOUND)


        password_check = user.check_password(password)

        if not password_check:
            return Response({'error': 'Şifre yanlış. Hesap silinemedi.'}, status=status.HTTP_401_UNAUTHORIZED)

        user.delete()
        return Response({'message': 'Hesap başarıyla silindi.'}, status=status.HTTP_200_OK)


from rest_framework.permissions import BasePermission


class IsAdminOrSelf(BasePermission):

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        return obj == request.user



from django.utils import timezone
from django.db.models import Prefetch

class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer

    def get_permissions(self):
        if self.action == 'list':
            return [IsAdminUser()]
        if self.action in ['retrieve', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated(), IsAdminOrSelf()]
        return super().get_permissions()



    @action(detail=False, methods=['get'], url_path='profile')
    def profile(self, request):
        user = request.user

        if not user.is_authenticated:
            return Response(
                {"error": "Kullanıcı doğrulanmadı. Lütfen giriş yapın."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        now = timezone.localtime(timezone.now())
        today = now.date()
        current_time = now.time()

        # TEMEL KULLANICI BİLGİLERİ
        data = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "credit": user.credit,
        }

        # 👑 EN ÖNEMLİ OPTİMİZASYON:
        # hatirlatma_tarihleri DB'den filtrelenmiş şekilde gelsin
        hatirlaticilar_toplam = Hatirlaticilar.objects.filter(arac__user=user)

        hatirlaticilar = hatirlaticilar_toplam.filter(is_removed=False).prefetch_related(
            Prefetch(
                "hatirlatma_tarihleri",
                queryset=HatirlatmaTarihleri.objects.filter(is_stopped=False),
                to_attr="aktif_tarihler",  # Python tarafında direkt liste olarak gelir
            )
        )

        aktif_sayisi = 0

        for h in hatirlaticilar:
            tarihler = h.aktif_tarihler  # DB’ye gitmez, RAM’den okur

            if not tarihler:
                continue

            # Tüm filtre tek sorguda değil, RAM’de list üzerinden yapılır.
            # Çünkü artık tarihler zaten filtrelenmiş şekilde RAM'de duruyor.
            for t in tarihler:
                if t.tarih > today:
                    aktif_sayisi += 1
                    break

                if t.tarih == today and t.saat > current_time:
                    aktif_sayisi += 1
                    break

        data["aktıf_hatirlatici"] = aktif_sayisi
        data["toplam_olusturulan_hatirlatici"] = hatirlaticilar_toplam.count()

        return Response(data)


# onesognals token yoksa kaydet dgeısmemısse kaydet


class SinalsTokenCreateOrControl(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        player_id = request.data.get("player_id")

        if not player_id:
            return Response({"error": "player_id required"}, status=400)

        user = request.user

        # değişmişse güncelle
        if user.player_id != player_id:
            user.player_id = player_id
            user.save()

        return Response({"status": "ok"})







from datetime import timedelta

from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import PasswordResetCode, CustomUser
import random
from django.conf import settings

from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError


class PasswordResetViewSet(viewsets.GenericViewSet):
    @action(detail=False, methods=['post'], url_path='request-reset')
    def request_reset(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'email': ['E-posta gerekli.']}, status=status.HTTP_400_BAD_REQUEST)

        # Validate email format
        try:
            validate_email(email)
        except DjangoValidationError:
            #print("------hata-----")
            return Response({'email': ['Geçerli bir e-posta adresi girin.']}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'email': ['Bu e-posta adresine sahip bir kullanıcı bulunamadı.']},
                            status=status.HTTP_404_NOT_FOUND)

        code = '{:06d}'.format(random.randint(0, 999999))  # 6 haneli kod oluşturma
        PasswordResetCode.objects.create(
            user=user,
            code=code,
            expires_at=timezone.now() + timedelta(minutes=15)
        )

        email_body = f"""
        <div style="font-family: Arial, sans-serif; color: #14171a; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 8px; background-color: #f9f9f9;">
            <h2 style="text-align: center; color: #1D64F2;">Aklımda Uygulaması - Şifre Sıfırlama</h2>
            <p style="font-size: 16px; color: #14171a;">Merhaba,</p>
            <p style="font-size: 16px; color: #14171a;">Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>
            <p style="font-size: 24px; font-weight: bold; text-align: center; padding: 10px; background-color: #E7F3FE; border: 1px solid #1D64F2; border-radius: 4px; color: #1D64F2;">{code}</p>
            <p style="font-size: 16px; color: #14171a;">Eğer bu işlemi siz yapmadıysanız, bu e-postayı dikkate almayın.</p>
            <p style="font-size: 16px; color: #14171a;">Teşekkürler,<br>Aklımda Destek Ekibi</p>
            <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 20px 0;">
            <p style="font-size: 12px; text-align: center; color: #999;">Bu e-posta, Aklımda Uygulamasından bir şifre sıfırlama isteğiyle ilgili gönderilmiştir.</p>
        </div>
        """

        send_mail(
            'Şifre Sıfırlama İsteği',
            '',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            html_message=email_body
        )

        return Response({'detail': 'Şifre sıfırlama kodu e-posta adresinize gönderildi.'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='reset-password')
    def reset_password(self, request):
        code = request.data.get('code')
        new_password = request.data.get('new_password')

        if not code or not new_password:
            return Response({'detail': 'Code and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reset_code = PasswordResetCode.objects.get(code=code)
        except PasswordResetCode.DoesNotExist:
            return Response({'detail': 'Invalid or expired code.'}, status=status.HTTP_400_BAD_REQUEST)

        if not reset_code.is_valid():
            return Response({'detail': 'Code has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        user = reset_code.user
        user.set_password(new_password)
        user.save()

        # Code is used, so we delete it
        reset_code.delete()

        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)


# bize ulaşın

from .models import Iletisim
from .serializers import IletisimSerializers
class IletisimViewSet(viewsets.ModelViewSet):
    queryset = Iletisim.objects.all().order_by('id')
    serializer_class = IletisimSerializers
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(user=user)


# güncel paylaşımlar

from .models import CurrentPosts
from .serializers import CurrentPostSerializers,CurrentPostTop10Serializers

class CurrentPostViewSet(viewsets.ModelViewSet):
    queryset = CurrentPosts.objects.filter(is_removed=False).order_by('order')
    serializer_class = CurrentPostSerializers
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'], url_path='current-posts-top10')
    def current_post_top10(self, request):
        queryset = CurrentPosts.objects.filter(is_removed=False).order_by('order')[:10]
        serializer = CurrentPostTop10Serializers(queryset, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='full')
    def full(self, request):
        queryset = CurrentPosts.objects.filter(is_removed=False).order_by('order')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



# araclar

from .models import Araclar
from .serializers import AraclarSerializers

from .models import Hatirlaticilar
from .serializers import HatirlaticilarSerializer,HatirlaticilarListSerializer

from django.forms.models import model_to_dict

class AraclarViewSet(viewsets.ModelViewSet):
    queryset = Araclar.objects.filter(is_removed=False).order_by('-id')
    serializer_class = AraclarSerializers
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def perform_update(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'], url_path='araclar-full')
    def araclar_full(self,request):
        araclar = Araclar.objects.filter(user=request.user,is_removed=False).order_by('-id')
        serializer = self.get_serializer(araclar, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['put'], url_path='araci-sil')
    def araci_sil(self, request, pk=None):

        try:
            arac = Araclar.objects.get(id=pk, user=request.user)
        except Araclar.DoesNotExist:
            return Response(
                {"error": "Belirtilen ID'ye sahip arac bulunamadı."},
                status=status.HTTP_404_NOT_FOUND,
            )

        arac.is_removed = True
        arac.save()

        arac.hatirlatma_arac.update(is_removed=True)

        return Response(
            {"success": f"Araç {pk} başarıyla silindi."},
            status=status.HTTP_200_OK,
        )


    @action(detail=True, methods=['get'], url_path='arac-hatirlaticilari')
    def arac_hatirlaticilari(self, request, pk=None):
        try:
            arac = Araclar.objects.get(id=pk, user=request.user)
        except Araclar.DoesNotExist:
            return Response(
                {"error": "Belirtilen ID'ye sahip arac bulunamadı."},
                status=status.HTTP_404_NOT_FOUND,
            )



        arac_serializers = AraclarSerializers(arac)

        hatirlaticilar_data= arac.hatirlatma_arac.filter(is_removed=False)

        hatirlaticilar_serializers = HatirlaticilarListSerializer(hatirlaticilar_data, many=True)

        data = {
            'arac':arac_serializers.data,
            'hatirlaticilar':hatirlaticilar_serializers.data
        }

        return Response(data, status=status.HTTP_200_OK)


# hatılatıcılar


class HatirlaticilarViewSet(viewsets.ModelViewSet):
    queryset = Hatirlaticilar.objects.all().order_by('id')
    serializer_class = HatirlaticilarSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = request.user

        # ---- KREDİ KONTROLÜ ----
        if user.credit <= 0:
            return Response(
                {"detail": "Yeterli krediniz yok. Hatırlatıcı oluşturulamadı."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ---- KREDİ YETERLİ → Serializer'i çalıştır ----
        return super().create(request, *args, **kwargs)

    @action(detail=False,methods=['get'],url_path='hatirlaticilarim')
    def hatirlaticilarim(self,request):
        hatirlaticilarim = (
            Hatirlaticilar.objects
            .filter(is_removed=False, arac__user=request.user)
            .select_related("arac")
            .prefetch_related(
                Prefetch(
                    'hatirlatma_tarihleri',
                    queryset=HatirlatmaTarihleri.objects.order_by('tarih')
                )
            )
            .order_by('-id')
        )
        serializer = self.get_serializer(hatirlaticilarim, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['patch'], url_path='hatirlatici-delete')
    def hatirlatici_delete(self,request, pk=None):
        try:
            hatirlaticilar=Hatirlaticilar.objects.get(id=pk, arac__user=request.user)
        except Hatirlaticilar.DoesNotExist:
            return Response(
                {"error": "Belirtilen ID'ye sahip hatirlatici bulunamadı."},
                status=status.HTTP_404_NOT_FOUND,
            )

        hatirlaticilar.is_removed = True
        hatirlaticilar.save()

        return Response(
            {"success": f"Hatirlatici {pk} başarıyla silindi."},
            status=status.HTTP_200_OK,
        )

from .models import HatirlatmaTarihleri

class HatirlatmaTarihiDurdur(APIView):
    permission_classes = [IsAuthenticated]  # önemli

    def post(self, request):
        liste = request.data.get('list')

        # doğrulama
        if not isinstance(liste, list):
            return Response({"error": "list bir dizi olmalıdır"}, status=400)

        try:
            liste = [int(i) for i in liste]
        except:
            return Response({"error": "ID değerleri integer olmalıdır"}, status=400)

        # sadece kullanıcının kendi kayıtları
        qs = HatirlatmaTarihleri.objects.filter(
            id__in=liste,
            hatirlatici__arac__user=request.user
        )

        qs.update(is_stopped=True)

        return Response(
            {'success': 'Gönderilen hatırlatma tarihleri durduruldu'},
            status=status.HTTP_200_OK
        )





from .models import Notifications
from .serializers import NotificationsSerializers


# example bıldırım
from django.conf import settings
from datetime import datetime, timedelta


import requests  # requests modülü kullanılacak

PUSHY_API_KEY = settings.PUSHY_API_KEY


class NotificationsExample(APIView):
    def post(self, request):
        bugun = timezone.now().date()

        hatirlatma_tarihleri = HatirlatmaTarihleri.objects.filter(
            is_stopped=False,
            tarih=bugun,
            hatirlatici__is_removed=False,
        )

        gonderilen = 0
        hatalar = []

        for data in hatirlatma_tarihleri:
            try:
                user = data.hatirlatici.arac.user
                token = user.player_id

                if not token:
                    hatalar.append({"hatirlatma_id": data.id, "error": "Token yok"})
                    continue

                hatirlatma_turu = data.hatirlatici.hatirlatma_turu
                hatirlatma_turu_cap = hatirlatma_turu.capitalize()
                arac_plakasi = data.hatirlatici.arac.arac_plakasi

                Notifications.objects.create(hatirlatma_tarihleri=data)

                payload = {
                    "to": token,
                    "data": {
                        "title": f"{hatirlatma_turu_cap} Hatırlatması",
                        "message": f"{arac_plakasi} plakalı aracınız için {hatirlatma_turu} ile ilgili gerekli kontrolleri yapmayı unutmayın."
                    }
                }

                response = requests.post(
                    f"https://api.pushy.me/push?api_key={PUSHY_API_KEY}",
                    json=payload,
                    timeout=15
                )

                if response.status_code == 200:
                    gonderilen += 1
                else:
                    hatalar.append({
                        "hatirlatma_id": data.id,
                        "status": response.status_code,
                        "error": response.text
                    })

            except Exception as e:
                hatalar.append({
                    "hatirlatma_id": data.id,
                    "error": str(e)
                })

        return Response({
            "durum": "ok",
            "toplam": hatirlatma_tarihleri.count(),
            "gonderilen": gonderilen,
            "hatalar": hatalar
        })



class NotifiticationList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        data = (
            Notifications.objects
            .filter(hatirlatma_tarihleri__hatirlatici__arac__user=user).order_by('id')
        )

        serializer = NotificationsSerializers(data, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)







