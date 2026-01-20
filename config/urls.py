from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views

urlpatterns = [
    # --- Admin Panel ---
    path("admin/", admin.site.urls),

    # --- Include Core App URLs ---
    # This line connects all the paths defined in core/urls.py (login, users, exams, etc.)
    path("", include("core.urls")),

    # --- Password Reset Handling ---
    # These standard Django views are kept here for global access
    path("accounts/reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(template_name='registration/password_reset_confirm.html'), name='password_reset_confirm'),
    path("accounts/reset/done/", auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
]