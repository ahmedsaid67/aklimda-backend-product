from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import CustomUser,Contact,SessionToken,Iletisim,CurrentPosts,Araclar,Hatirlaticilar,HatirlatmaTarihleri,Notifications



admin.site.register(CustomUser)
admin.site.register(Iletisim)
admin.site.register(Contact)
admin.site.register(SessionToken)
admin.site.register(CurrentPosts)
admin.site.register(Araclar)
admin.site.register(Hatirlaticilar)
admin.site.register(HatirlatmaTarihleri)
admin.site.register(Notifications)

