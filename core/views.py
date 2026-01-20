import threading
import json
import math
import html
from datetime import timedelta
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.views import LoginView
from django.http import JsonResponse
from django.utils.html import linebreaks
from django.conf import settings 

# --- Google Gemini Import ---
import google.generativeai as genai 

from .forms import UserUpdateForm, EmailOrUsernameAuthenticationForm, AdminUserCreationForm, AdminUserEditForm
from .zoho_service import send_zoho_email
from .models import ExamSession, ExamAssignment
from .ai_agents import orchestrated_exam_flow
from django.db import close_old_connections

# --- HELPER: ROBUST ANSWER CHECKING ---
def check_answer_match(user_ans, correct_ans, options=[]):
    """
    Robust comparison for MCQ answers.
    Handles: Case, Whitespace, HTML Entities, Option Letters (A vs Answer Text).
    """
    if not user_ans or not correct_ans:
        return False
        
    u_val = html.unescape(str(user_ans)).strip().lower()
    c_val = html.unescape(str(correct_ans)).strip().lower()
    
    # 1. Exact Text Match
    if u_val == c_val:
        return True
        
    # 2. Soft Match (Handle "A. Text" vs "Text")
    def clean_prefix(text):
        if len(text) > 2 and text[1] in ['.', ')', ' ']:
            return text[2:].strip()
        return text
    
    if clean_prefix(u_val) == clean_prefix(c_val):
        return True

    # 3. Index/Letter Match
    # If Correct Answer is "B" (index 1), check if User Answer matches Options[1]
    c_index = -1
    if len(c_val) == 1 and 'a' <= c_val <= 'z':
        c_index = ord(c_val) - ord('a')
    
    if c_index != -1 and options and 0 <= c_index < len(options):
        opt_text = html.unescape(str(options[c_index])).strip().lower()
        if u_val == opt_text or u_val == clean_prefix(opt_text):
            return True

    return False

# --- CUSTOM LOGIN VIEW ---
class CustomLoginView(LoginView):
    authentication_form = EmailOrUsernameAuthenticationForm
    template_name = 'registration/login.html'
    redirect_authenticated_user = True

# --- CORE USER VIEWS ---

@login_required
def home(request):
    """
    Admin/HR Dashboard with real-time metrics and AI Status check.
    """
    # Redirect 'User' group members directly to their dashboard
    if request.user.groups.filter(name='User').exists():
        return redirect('candidate_dashboard')
    
    # --- 1. DETERMINE SCOPE (Admin vs HR) ---
    if request.user.is_superuser:
        # Admin sees ALL data
        exams_qs = ExamSession.objects.exclude(status='CONFIGURATION')
        assignments_qs = ExamAssignment.objects.all()
    else:
        # HR sees ONLY their own data
        exams_qs = ExamSession.objects.filter(user=request.user).exclude(status='CONFIGURATION')
        assignments_qs = ExamAssignment.objects.filter(assigned_by=request.user)

    # --- 2. CALCULATE METRICS ---
    now = timezone.now()
    week_ago = now - timedelta(days=7)

    # Card 1: Assessments Created
    assessments_total = exams_qs.count()
    assessments_recent = exams_qs.filter(created_at__gte=week_ago).count()

    # Card 2: Assignments
    assignments_total = assignments_qs.count()
    assignments_recent = assignments_qs.filter(assigned_at__gte=week_ago).count()

    # Card 3: Candidates (System-wide stat)
    total_candidates = User.objects.filter(groups__name='User').count()
    new_candidates_week = User.objects.filter(groups__name='User', date_joined__gte=week_ago).count()

    # --- 4. AI AGENT STATUS CHECK ---
    ai_status = "Offline"
    ai_status_color = "#ef4444" # Red
    ai_msg = "Connection Failed"

    try:
        # Fetch Key (Ensure GEMINI_API_KEY is in your settings.py)
        api_key = getattr(settings, 'GEMINI_API_KEY', None)
        
        if api_key:
            genai.configure(api_key=api_key)
            # FIX: list_models does not accept 'limit'.
            # We simply iterate once to verify connectivity.
            for m in genai.list_models():
                break
            
            ai_status = "Working Great"
            ai_status_color = "#10b981" # Green
            ai_msg = "" # Cleared "System Operational" text per request
        else:
            ai_msg = "API Key Missing"
    except Exception as e:
        ai_msg = "API Error"
        print(f"AI Check Failed: {e}")

    # --- 3. RECENT ACTIVITY FEED ---
    # Fetch recent 5 exams and recent 5 assignments, then merge and sort
    recent_exams = exams_qs.order_by('-created_at')[:5]
    recent_assignments = assignments_qs.order_by('-assigned_at')[:5]
    
    activities = []
    
    for e in recent_exams:
        activities.append({
            'type': 'exam',
            'icon': '✨',
            'title': f"Generated Exam: {e.coding_languages or 'General'} ({e.difficulty_level})",
            'user': e.user.username,
            'time': e.created_at
        })
        
    for a in recent_assignments:
        activities.append({
            'type': 'assign',
            'icon': '📧',
            'title': f"Assigned Exam to {a.candidate.username}",
            'user': a.assigned_by.username,
            'time': a.assigned_at
        })

    # Sort combined list by time descending and take top 8
    activities.sort(key=lambda x: x['time'], reverse=True)
    activities = activities[:8]

    context = {
        'assessments_total': assessments_total,
        'assessments_recent': assessments_recent,
        'assignments_total': assignments_total,
        'assignments_recent': assignments_recent,
        'total_candidates': total_candidates,
        'new_candidates_week': new_candidates_week,
        'ai_status': ai_status,           
        'ai_status_color': ai_status_color, 
        'ai_msg': ai_msg,                 
        'activities': activities
    }
    return render(request, "home.html", context)

@login_required
def profile(request):
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect(f"{reverse('profile')}#update-profile")
    else:
        form = UserUpdateForm(instance=request.user)
    return render(request, 'profile.html', {'form': form})

@login_required
def settings_view(request):
    if request.method == 'POST':
        try:
            difficulty = request.POST.get('level')
            experience = request.POST.get('experience')
            num_questions = request.POST.get('num_questions')
            
            # Capture multiple languages properly
            languages_list = request.POST.getlist('languages')
            languages = ", ".join(languages_list) if languages_list else None

            instructions = request.POST.get('instructions')
            
            repeated_allowed = request.POST.get('repeated_allowed') == 'on'
            
            # --- FORCED VALUES (Hidden from UI) ---
            # mcq = request.POST.get('mcq') == 'on' 
            # mcq_coding = request.POST.get('mcq_coding') == 'on'
            mcq = True 
            mcq_coding = False
            
            general_topic = request.POST.get('general_topic') == 'on'

            # Create a CONFIGURATION session (Ignored by Generator Page)
            ExamSession.objects.create(
                user=request.user,
                difficulty_level=difficulty,
                experience_level=experience,
                num_questions=num_questions,
                repeated_questions_allowed=repeated_allowed,
                mcq_format=mcq,
                mcq_coding_format=mcq_coding,
                general_topic=general_topic,
                coding_languages=languages,
                specific_instructions=instructions,
                status='CONFIGURATION' 
            )
            messages.success(request, "Configuration Saved Successfully!")
            return redirect('settings')
        except Exception as e:
            messages.error(request, f"Error saving configuration: {str(e)}")
            return redirect('settings')

    last_exam = ExamSession.objects.filter(user=request.user).last()
    return render(request, 'settings.html', {'last_exam': last_exam})

# --- EXAM GENERATION & MANAGEMENT VIEWS ---

def is_admin_or_hr(user):
    return user.is_superuser or user.groups.filter(name='Hr').exists()

@login_required
def generate_exam(request):
    """
    Renders the Generate Exam page. 
    """
    if request.user.groups.filter(name='User').exists():
        messages.error(request, "You are not authorized to access this page.")
        return redirect('home')
    
    # Active Session (User Specific)
    active_session = ExamSession.objects.filter(
        user=request.user, 
        status__in=['PROCESSING', 'PENDING']
    ).order_by('-created_at').first()
    
    # Fetch Candidates for Assignment Modal (ONLY 'User' role)
    candidates = User.objects.filter(groups__name='User')

    context = {
        'active_session_id': active_session.id if active_session else None,
        'candidates': candidates
    }
    return render(request, 'generate_exam.html', context)

@login_required
@user_passes_test(is_admin_or_hr)
def previous_exams(request):
    """
    List previous exams. Admin sees ALL. HR sees OWN.
    """
    if request.user.is_superuser:
        exams = ExamSession.objects.filter(status='COMPLETED').order_by('-created_at')
    else:
        exams = ExamSession.objects.filter(user=request.user, status='COMPLETED').order_by('-created_at')
    
    return render(request, 'previous_exams.html', {'exams': exams})

@login_required
@user_passes_test(is_admin_or_hr)
def preview_exam(request, session_id):
    """
    Detailed view of a specific generated exam with Assign option.
    """
    # 1. Fetch Exam based on permissions
    if request.user.is_superuser:
        exam = get_object_or_404(ExamSession, id=session_id)
    else:
        exam = get_object_or_404(ExamSession, id=session_id, user=request.user)

    # 2. Parse the stored result_html (JSON string)
    exam_content = {}
    if exam.result_html:
        try:
            exam_content = json.loads(exam.result_html)
        except json.JSONDecodeError:
            exam_content = {'header_html': '', 'questions_html': 'Error loading exam content.'}

    # 3. Fetch Candidates for Assign Modal (ONLY 'User' role)
    candidates = User.objects.filter(groups__name='User')

    context = {
        'exam': exam,
        'exam_content': exam_content,
        'candidates': candidates
    }
    return render(request, 'preview_exam.html', context)

@login_required
def start_exam_generation(request):
    if request.method == 'POST':
        last_config = ExamSession.objects.filter(user=request.user).exclude(status='PROCESSING').last()
        if not last_config:
            return JsonResponse({'status': 'error', 'message': 'Please save Settings first.'})

        new_session = ExamSession.objects.create(
            user=request.user,
            difficulty_level=last_config.difficulty_level,
            experience_level=last_config.experience_level,
            num_questions=last_config.num_questions,
            coding_languages=last_config.coding_languages,
            specific_instructions=last_config.specific_instructions,
            mcq_format=True,         # Enforced
            mcq_coding_format=False, # Enforced
            general_topic=last_config.general_topic,
            repeated_questions_allowed=last_config.repeated_questions_allowed,
            status='PENDING' 
        )

        # UPDATED: Thread started WITHOUT daemon=True
        # This ensures the thread runs to completion even if the request finishes
        thread = threading.Thread(target=orchestrated_exam_flow, args=(new_session.id,))
        thread.start()

        return JsonResponse({'status': 'started', 'session_id': new_session.id})
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@login_required
def cancel_exam_generation(request):
    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        if session_id:
            try:
                session = ExamSession.objects.get(id=session_id, user=request.user)
                session.status = 'CANCELLED'
                session.save()
                return JsonResponse({'status': 'cancelled'})
            except ExamSession.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Session not found'})
    return JsonResponse({'status': 'error'}, status=400)

@login_required
def delete_exam(request):
    if request.method == 'POST':
        exam_id = request.POST.get('exam_id')
        try:
            exam = ExamSession.objects.get(id=exam_id)
            if request.user.is_superuser or exam.user == request.user:
                exam.delete()
                return JsonResponse({'status': 'success', 'message': 'Exam deleted.'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Permission denied.'}, status=403)
        except ExamSession.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Exam not found.'}, status=404)
    return JsonResponse({'status': 'error'}, status=400)

@login_required
def check_exam_status(request):
    session_id = request.GET.get('session_id')
    if session_id:
        try:
            session = ExamSession.objects.get(id=session_id, user=request.user)
            return JsonResponse({
                'status': session.status,
                'html': session.result_html if session.status == 'COMPLETED' else None
            })
        except ExamSession.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Not found'})
    return JsonResponse({'status': 'error'}, status=400)

@login_required
def assign_exam(request):
    if request.method == 'POST':
        exam_id = request.POST.get('exam_id')
        user_id = request.POST.get('user_id')
        custom_message = request.POST.get('message', '').strip() 
        
        try:
            exam = ExamSession.objects.get(id=exam_id)
            candidate = User.objects.get(id=user_id)
            
            ExamAssignment.objects.create(
                exam=exam,
                candidate=candidate,
                assigned_by=request.user
            )
            
            domain = get_current_site(request).domain
            protocol = 'https' if request.is_secure() else 'http'
            login_url = f"{protocol}://{domain}{reverse('login')}"
            
            note_html = ""
            if custom_message:
                msg_body = custom_message.replace('\n', '<br>')
                note_html = f"<li><strong>Note from Admin:</strong> {msg_body}</li>"

            subject = f"New Exam Assigned: {exam.coding_languages or 'Technical Assessment'}"
            
            html_content = f"""
            <h3>Hello {candidate.username},</h3>
            <p>You have been assigned a new technical exam.</p>
            <ul>
                <li><strong>Topic:</strong> {exam.coding_languages or 'General'}</li>
                <li><strong>Username:</strong> {candidate.username}</li>
                {note_html}
            </ul>
            <p>Please log in to your dashboard to take the test.</p>
            <p><a href="{login_url}" style="background:#4f46e5;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Go to Exam Portal</a></p>
            """
            
            send_zoho_email(candidate.email, subject, html_content)
            
            return JsonResponse({'status': 'success', 'message': f'Exam assigned to {candidate.username} and email sent.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error'}, status=400)

# --- CANDIDATE & EXAM INTERFACE ---

@login_required
def candidate_dashboard(request):
    assignments = ExamAssignment.objects.filter(
        candidate=request.user,
        is_completed=False
    ).select_related('exam').order_by('-assigned_at')
    
    # Calculate duration dynamically
    for assign in assignments:
        assign.calculated_duration = int(assign.exam.num_questions * 2.5)

    return render(request, 'users/candidate_dashboard.html', {'assignments': assignments})

@login_required
def take_exam(request, assignment_id):
    """
    Manages the exam taking process with robust error handling.
    """
    assignment = get_object_or_404(ExamAssignment, id=assignment_id, candidate=request.user)
    
    # --- 1. INTEGRITY CHECK ---
    if not assignment.exam or not assignment.exam.exam_data:
        messages.error(request, "This exam content is missing or was deleted. The assignment has been removed.")
        assignment.delete() # Auto-cleanup
        return redirect('candidate_dashboard')

    # --- 2. SECURITY CHECK ---
    if assignment.is_completed:
        messages.warning(request, "You have already completed this exam.")
        return redirect('candidate_history') 

    # --- 3. DATA LOADING ---
    try:
        exam_data = json.loads(assignment.exam.exam_data)
        questions = exam_data.get('questions', [])
        
        if not questions:
            raise ValueError("No questions found in exam data")

    except (TypeError, json.JSONDecodeError, ValueError) as e:
        print(f"Exam Load Error: {e}")
        messages.error(request, "Error loading exam data. It has been removed from your list.")
        assignment.delete() # Auto-cleanup
        return redirect('candidate_dashboard')

    # Calculate Duration (2.5 mins/question)
    minutes_allowed = assignment.exam.num_questions * 2.5
    total_seconds_allowed = int(minutes_allowed * 60)

    # --- 4. SUBMISSION LOGIC ---
    if request.method == 'POST':
        correct_points = 0
        total_questions = len(questions)
        submission_data = {}

        for q in questions:
            user_answer = request.POST.get(f'answer_{q["id"]}', '').strip()
            correct_answer = q.get('correct_answer', '').strip()
            q_type = q.get('type', 'MCQ')

            is_correct = False
            if q_type == 'MCQ':
                # --- UPDATED GRADING LOGIC ---
                options = q.get('options', [])
                if check_answer_match(user_answer, correct_answer, options):
                    is_correct = True
                    correct_points += 1
            
            submission_data[q["id"]] = {
                "user_answer": user_answer,
                "is_correct": is_correct,
                "type": q_type
            }

        final_score = 0.0
        if total_questions > 0:
            final_score = (correct_points / total_questions) * 100
        
        assignment.score = round(final_score, 2)
        assignment.is_completed = True
        assignment.result_data = json.dumps(submission_data)
        assignment.save()
        
        # --- NEW: SEND RESULT EMAILS ---
        try:
            # 1. Candidate Email
            subject_candidate = f"Exam Completed: {assignment.exam.coding_languages or 'Technical Assessment'}"
            content_candidate = f"""
                <h3>Exam Completed</h3>
                <p>Dear {assignment.candidate.username},</p>
                <p>You have successfully completed the assessment.</p>
                <ul>
                    <li><strong>Exam:</strong> {assignment.exam.coding_languages or 'General'}</li>
                    <li><strong>Score:</strong> {assignment.score}%</li>
                    <li><strong>Date:</strong> {timezone.now().strftime('%Y-%m-%d %H:%M')}</li>
                </ul>
                <p>You can view detailed results in your dashboard history.</p>
            """
            if assignment.candidate.email:
                send_zoho_email(assignment.candidate.email, subject_candidate, content_candidate)

            # 2. Assignor Email
            if assignment.assigned_by and assignment.assigned_by.email:
                subject_admin = f"Result Alert: {assignment.candidate.username} - {assignment.score}%"
                content_admin = f"""
                    <h3>Candidate Assessment Finished</h3>
                    <p><strong>Candidate:</strong> {assignment.candidate.username} ({assignment.candidate.email})</p>
                    <p><strong>Exam:</strong> {assignment.exam.coding_languages or 'General'}</p>
                    <p><strong>Score:</strong> {assignment.score}%</p>
                    <p>Please log in to the admin dashboard to review the full details.</p>
                """
                send_zoho_email(assignment.assigned_by.email, subject_admin, content_admin)
        except Exception as e:
            print(f"Email Notification Failed: {e}")
        # -------------------------------

        messages.success(request, f"Exam submitted successfully! Score: {assignment.score}%")
        return redirect('candidate_dashboard')

    # --- 5. RENDER LOGIC ---
    if request.GET.get('start') == 'true':
        # Init start time if fresh
        if not assignment.start_time:
            assignment.start_time = timezone.now()
            assignment.save()
        
        # Calc remaining seconds
        elapsed = timezone.now() - assignment.start_time
        elapsed_seconds = elapsed.total_seconds()
        remaining_seconds = max(0, total_seconds_allowed - elapsed_seconds)

        # Force close if expired
        if remaining_seconds <= 0:
            remaining_seconds = 0 # JS will auto-submit

        context = {
            'assignment': assignment,
            'questions': questions,
            'hide_sidebar': True,
            'timer_seconds': int(remaining_seconds)
        }
        return render(request, 'exams/take_exam.html', context)
    else:
        return render(request, 'exams/exam_instructions.html', {
            'assignment': assignment,
            'duration_minutes': int(minutes_allowed)
        })

@login_required
def candidate_history(request):
    completed_assignments = ExamAssignment.objects.filter(
        candidate=request.user,
        is_completed=True
    ).select_related('exam').order_by('-assigned_at')
    return render(request, 'users/candidate_history.html', {'assignments': completed_assignments})

@login_required
def exam_result(request, assignment_id):
    if request.user.is_superuser:
        assignment = get_object_or_404(ExamAssignment, id=assignment_id)
    else:
        assignment = get_object_or_404(ExamAssignment, id=assignment_id, candidate=request.user)

    if not assignment.is_completed:
        messages.warning(request, "This exam is not yet completed.")
        return redirect('candidate_dashboard')

    try:
        exam_data = json.loads(assignment.exam.exam_data)
        questions = exam_data.get('questions', [])
        user_results = json.loads(assignment.result_data) if assignment.result_data else {}

        detailed_questions = []
        for q in questions:
            q_id = str(q['id'])
            res = user_results.get(q_id, {})
            
            # --- FIX FOR DISPLAYING "INCORRECT" ON VISUALLY CORRECT ANSWERS ---
            is_correct = res.get('is_correct', False)
            
            # Double check logic to handle historical data mismatch
            if not is_correct:
                u_ans = res.get('user_answer', '')
                c_ans = q.get('correct_answer', '')
                opts = q.get('options', [])
                if check_answer_match(u_ans, c_ans, opts):
                    is_correct = True

            detailed_questions.append({
                'q_text': q.get('question_text'),
                'options': q.get('options', []),
                'correct_answer': q.get('correct_answer'),
                'user_answer': res.get('user_answer', 'Not Answered'),
                'is_correct': is_correct,
                'type': q.get('type'),
                'explanation': q.get('explanation', '')
            })
    except Exception as e:
        messages.error(request, f"Error loading results: {e}")
        return redirect('candidate_history')

    return render(request, 'exams/exam_result.html', {'assignment': assignment, 'detailed_questions': detailed_questions})

# --- USER MANAGEMENT & UTILS ---

@login_required
def trigger_password_reset(request):
    user = request.user
    if not user.email:
        messages.error(request, "Please add an email address to your profile first.")
        return redirect(f"{reverse('profile')}#update-profile")
    
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    protocol = 'https' if request.is_secure() else 'http'
    link = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
    reset_url = f"{protocol}://{domain}{link}"
    
    subject = "Reset your password"
    html_content = f"""<p>Hello {user.username},</p>
    <p>You requested to update your password. <a href="{reset_url}">Click here</a>.</p>"""
    
    success, message = send_zoho_email(user.email, subject, html_content)
    if success:
        messages.success(request, f"A password reset link has been sent to {user.email}")
    else:
        messages.error(request, f"Failed to send email: {message}")
    return redirect(f"{reverse('profile')}#reset-password")

@user_passes_test(is_admin_or_hr)
def user_list(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'users/user_list.html', {'users': users})

@user_passes_test(is_admin_or_hr)
def user_add(request):
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "New user created successfully.")
            return redirect('user_list')
    else:
        form = AdminUserCreationForm(user=request.user)
    return render(request, 'users/user_form.html', {'form': form, 'title': 'Add New User', 'is_edit': False})

@user_passes_test(is_admin_or_hr)
def user_edit(request, pk):
    user_to_edit = get_object_or_404(User, pk=pk)
    
    if not request.user.is_superuser:
        if user_to_edit.is_superuser or user_to_edit.groups.filter(name='Hr').exists():
            messages.error(request, "You do not have permission to edit this user.")
            return redirect('user_list')

    if request.method == 'POST':
        form = AdminUserEditForm(request.POST, instance=user_to_edit, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, f"User {user_to_edit.username} updated successfully.")
            return redirect('user_list')
    else:
        form = AdminUserEditForm(instance=user_to_edit, user=request.user)
    
    return render(request, 'users/user_form.html', {
        'form': form, 
        'title': 'Edit User',
        'is_edit': True
    })

@user_passes_test(is_admin_or_hr)
def admin_trigger_password_reset(request, user_id):
    user = get_object_or_404(User, id=user_id)
    
    if not request.user.is_superuser:
        if user.is_superuser or user.groups.filter(name='Hr').exists():
            messages.error(request, "You do not have permission to reset this user's password.")
            return redirect('user_list')
    
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    protocol = 'https' if request.is_secure() else 'http'
    link = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
    reset_url = f"{protocol}://{domain}{link}"
    
    subject = "Password Reset Request (Admin Initiated)"
    html_content = f"""<p>Hello {user.username},</p>
    <p>An administrator has requested a password reset for your account.</p>
    <p>Please click the link below to set a new password:</p>
    <p><a href="{reset_url}">Reset Password</a></p>
    <p>If you did not request this, please contact the administrator.</p>"""
    
    success, message = send_zoho_email(user.email, subject, html_content)
    
    if success:
        messages.success(request, f"Reset link sent to {user.email}")
    else:
        messages.error(request, f"Failed to send email: {message}")
        
    return redirect('user_list')

@user_passes_test(is_admin_or_hr)
def user_delete(request, pk):
    user_to_delete = get_object_or_404(User, pk=pk)
    
    if user_to_delete == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect('user_list')

    if not request.user.is_superuser:
        if user_to_delete.is_superuser:
            messages.error(request, "You do not have permission to delete Administrators.")
            return redirect('user_list')
        
        if user_to_delete.groups.filter(name='Hr').exists():
            messages.error(request, "You do not have permission to delete other HR accounts.")
            return redirect('user_list')
    
    if request.method == 'POST':
        user_to_delete.delete()
        messages.success(request, f"User {user_to_delete.username} has been deleted.")
        return redirect('user_list')
    
    return render(request, 'users/user_confirm_delete.html', {'object': user_to_delete})