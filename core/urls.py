from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # --- Dashboard & User Profile ---
    path("", views.home, name="home"),
    path("profile/", views.profile, name="profile"),
    path("profile/reset-password/", views.trigger_password_reset, name="trigger_password_reset"),
    path("settings/", views.settings_view, name="settings"),

    # --- Candidate Experience ---
    path("dashboard/", views.candidate_dashboard, name="candidate_dashboard"),
    path("dashboard/history/", views.candidate_history, name="candidate_history"),
    path("exam/<int:assignment_id>/take/", views.take_exam, name="take_exam"),
    path("exam/<int:assignment_id>/result/", views.exam_result, name="exam_result"),

    # --- Authentication ---
    path("login/", views.CustomLoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),

    # --- Admin User Management ---
    path("users/", views.user_list, name="user_list"),
    path("users/add/", views.user_add, name="user_add"),
    path("users/edit/<int:pk>/", views.user_edit, name="user_edit"), # <--- NEW
    path("users/delete/<int:pk>/", views.user_delete, name="user_delete"),
    path("users/admin-reset-password/<int:user_id>/", views.admin_trigger_password_reset, name="admin_trigger_password_reset"), # <--- NEW

    # --- Exam Management ---
    path("generate-exam/", views.generate_exam, name="generate_exam"),
    path("previous-exams/", views.previous_exams, name="previous_exams"),
    path("previous-exams/<int:session_id>/", views.preview_exam, name="preview_exam"),

    # --- Async API Endpoints ---
    path("api/exam/start/", views.start_exam_generation, name="start_exam_api"),
    path("api/exam/cancel/", views.cancel_exam_generation, name="cancel_exam_api"),
    path("api/exam/status/", views.check_exam_status, name="check_exam_status"),
    path("api/exam/assign/", views.assign_exam, name="assign_exam_api"),
    path("api/exam/delete/", views.delete_exam, name="delete_exam"),
]