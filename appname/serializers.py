from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import get_user_model


User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'password', 'first_name', 'last_name','credit')

    def validate(self, attrs):
        password = attrs.get('password')
        if password and len(password) < 8:
            raise serializers.ValidationError({"password": "Şifreniz en az 8 karakter uzunluğunda olmalıdır."})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = CustomUser(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance



from django.contrib.auth import authenticate
from rest_framework import serializers

class CustomAuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)

            if not user:
                raise serializers.ValidationError("Email veya şifre yanlış.", code='authorization')
        else:
            raise serializers.ValidationError("Email ve şifre alanları zorunludur.", code='authorization')

        attrs['user'] = user
        return attrs


# bize ulaşın

from .models import Iletisim

class IletisimSerializers(serializers.ModelSerializer):
    class Meta:
        model = Iletisim
        fields = '__all__'
        read_only_fields = ['user']


# güncel paylaşımlar

from .models import CurrentPosts

class CurrentPostSerializers(serializers.ModelSerializer):
    class Meta:
        model = CurrentPosts
        fields = ['id','title','image','explanations']
6

class CurrentPostTop10Serializers(serializers.ModelSerializer):
    class Meta:
        model = CurrentPosts
        fields = ['id','title','image']


# araclar

from .models import Araclar

class AraclarSerializers(serializers.ModelSerializer):

    class Meta:
        model = Araclar
        fields = '__all__'
        extra_kwargs = {
            'user': {'read_only': True},
            'arac_markasi': {'required': False, 'allow_blank': True},
            'arac_modeli': {'required': False, 'allow_blank': True},
            'arac_plakasi': {'required': False, 'allow_blank': True},
            'arac_no': {'required': False, 'allow_blank': True},
        }



# hatılatıcılar

from .models import HatirlatmaTarihleri,Hatirlaticilar
from django.utils import timezone


class HatirlatmaTarihleriSerializer(serializers.ModelSerializer):
    class Meta:
        model = HatirlatmaTarihleri
        fields = ['tarih','is_stopped','id']
        extra_kwargs = {
            'is_stopped': {'read_only': True},
            'id': {'read_only': True}
        }


from django.db import transaction

class HatirlaticilarSerializer(serializers.ModelSerializer):
    hatirlatma_tarihleri = HatirlatmaTarihleriSerializer(many=True)
    arac_id = serializers.PrimaryKeyRelatedField(
        queryset=Araclar.objects.all(),
        write_only=True,
        source="arac"
    )

    # GET için detay dönen alan
    arac = AraclarSerializers(read_only=True)

    class Meta:
        model = Hatirlaticilar
        fields = ['id','arac', 'hatirlatma_turu', 'son_tarih', 'hatirlatma_tarihleri','arac_id']



    @transaction.atomic
    def create(self, validated_data):
        request = self.context["request"]
        user = request.user

        # --- HATIRLATICI OLUŞTURMA ---
        tarih_listesi = validated_data.pop('hatirlatma_tarihleri', [])
        hatirlatici = Hatirlaticilar.objects.create(**validated_data)

        for tarih_data in tarih_listesi:
            HatirlatmaTarihleri.objects.create(
                hatirlatici=hatirlatici,
                **tarih_data
            )

        # --- KREDİ DÜŞ ---
        user.credit -= 1
        user.save()

        return hatirlatici


class HatirlaticilarListSerializer(serializers.ModelSerializer):
    hatirlatma_tarihleri = HatirlatmaTarihleriSerializer(many=True)

    class Meta:
        model = Hatirlaticilar
        fields = ['id', 'hatirlatma_turu', 'son_tarih', 'hatirlatma_tarihleri']

    def to_representation(self, instance):    # lıste ve retrıeve de arac alanının tum ozellıklerını ver demek.
        rep = super().to_representation(instance)
        # ID sırasına göre sıralama
        rep['hatirlatma_tarihleri'] = sorted(
            rep['hatirlatma_tarihleri'], key=lambda x: x['id']
        )
        return rep


# bildirimler

from .models import Notifications

class NotificationsSerializers(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ['id', 'explanation']