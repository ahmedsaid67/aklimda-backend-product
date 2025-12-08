# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CustomAuthToken, Logout, CustomUserViewSet, UserInfoView,PasswordResetViewSet,IletisimViewSet,Register,UserDelete,CurrentPostViewSet,\
    AraclarViewSet,HatirlaticilarViewSet,HatirlatmaTarihiDurdur,SinalsTokenCreateOrControl,NotificationsExample,NotifiticationList

from django.conf import settings
from django.conf.urls.static import static

# Router oluştur
router = DefaultRouter()
router.register(r'users', CustomUserViewSet, basename='user')
router.register(r'password-reset', PasswordResetViewSet, basename='password-reset')
router.register(r'iletisim', IletisimViewSet)
router.register(r'araclar', AraclarViewSet)
router.register(r'hatirlaticilar', HatirlaticilarViewSet)

router.register(r'current-post', CurrentPostViewSet, basename='current-post')

urlpatterns = [
    # auth apileri
    path('user-info/', UserInfoView.as_view(), name='user-info'),
    path('token/', CustomAuthToken.as_view(), name='api-token'),
    path('logout/', Logout.as_view(), name='logout'),
    path('register/', Register.as_view(), name='register'),
    path('user-delete/', UserDelete.as_view(), name='user-delete'),
    path('pushy-token-create-or-control/', SinalsTokenCreateOrControl.as_view(), name='pushy-token-create-or-control'),
    path('hatirlatma-tarihleri-durdur/',HatirlatmaTarihiDurdur.as_view(),name='hatirlatma-tarihleri-durdur'),
    path('', include(router.urls)),

    path('bildirim-example/', NotificationsExample.as_view(), name='bildirim-example'),
    path('notifications-list/', NotifiticationList.as_view(), name='notifications-list'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)