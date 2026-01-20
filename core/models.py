from django.db import models
from django.contrib.auth.models import User
import json

class ExamSession(models.Model):
    # --- CHOICES ---
    DIFFICULTY_CHOICES = [
        ('Beginner', 'Beginner'),
        ('Medium', 'Medium'),
        ('Advanced', 'Advanced'),
    ]

    EXPERIENCE_CHOICES = [
        ('Fresher', 'Fresher / < 1 Year'),
        ('1-3 Years', '1 - 3 Years'),
        ('4-5 Years', '4 - 5 Years'),
        ('5+ Years', 'Above 5 Years'),
    ]

    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('FAILED', 'Failed'),
        ('CONFIGURATION', 'Configuration'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='exam_sessions')
    
    difficulty_level = models.CharField(max_length=20, choices=DIFFICULTY_CHOICES)
    experience_level = models.CharField(max_length=20, choices=EXPERIENCE_CHOICES)
    
    num_questions = models.IntegerField()
    repeated_questions_allowed = models.BooleanField(default=False)
    mcq_format = models.BooleanField(default=False)
    mcq_coding_format = models.BooleanField(default=False)
    
    general_topic = models.BooleanField(default=False)
    coding_languages = models.CharField(max_length=255, blank=True, null=True)
    specific_instructions = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    result_html = models.TextField(blank=True, null=True)
    exam_data = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Exam ({self.difficulty_level}) - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

class ExamAssignment(models.Model):
    """
    Tracks exams assigned to specific candidates.
    """
    exam = models.ForeignKey(ExamSession, on_delete=models.CASCADE, related_name='assignments')
    candidate = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assigned_exams')
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assignments_created')
    
    attempts_allowed = models.IntegerField(default=1)
    attempts_used = models.IntegerField(default=0)
    
    # Timer Persistence
    start_time = models.DateTimeField(null=True, blank=True) # NEW FIELD
    
    is_completed = models.BooleanField(default=False)
    score = models.FloatField(blank=True, null=True)
    
    result_data = models.TextField(blank=True, null=True) 
    
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.candidate.username} - {self.exam}"