from django.contrib import admin
from .models import ExamSession

@admin.register(ExamSession)
class ExamSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'difficulty_level', 'experience_level', 'num_questions', 'created_at')
    list_filter = ('difficulty_level', 'experience_level', 'created_at')
    search_fields = ('user__username', 'coding_languages', 'specific_instructions')
    readonly_fields = ('created_at',)