from django import forms
from django.contrib.auth.models import User, Group
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db.models import Q

class EmailOrUsernameAuthenticationForm(AuthenticationForm):
    """
    Custom form that changes the label to 'Username or Email'.
    Used by CustomLoginView.
    """
    username = forms.CharField(
        label="Username or Email",
        widget=forms.TextInput(attrs={'class': 'form-input', 'autofocus': True})
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'class': 'form-input'})
    )

class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-input'}))
    first_name = forms.CharField(max_length=30, required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))
    last_name = forms.CharField(max_length=30, required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input'}),
        }
        help_texts = {
            'username': None,
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username:
            raise forms.ValidationError("Username cannot be blank.")
        if User.objects.filter(username__iexact=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email:
            raise forms.ValidationError("Email cannot be blank.")
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This email address is already associated with another account.")
        return email

class AdminUserCreationForm(UserCreationForm):
    """
    Form for Admins to add a new user.
    Extends UserCreationForm which handles the Password 1 & 2 validation automatically.
    Now includes Role selection.
    """
    ROLE_CHOICES = [
        ('User', 'User'),
        ('Hr', 'Hr'),
        ('Admin', 'Admin'),
    ]

    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-input'}))
    first_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))
    last_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))
    role = forms.ChoiceField(
        choices=ROLE_CHOICES, 
        required=True, 
        widget=forms.Select(attrs={'class': 'form-input'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'role']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input'}),
        }

    def __init__(self, *args, **kwargs):
        # Extract 'user' from kwargs before calling super
        self.current_user = kwargs.pop('user', None)
        super(AdminUserCreationForm, self).__init__(*args, **kwargs)
        
        # Apply the CSS class to ALL fields
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-input'

        # --- ROLE RESTRICTION LOGIC ---
        if self.current_user and not self.current_user.is_superuser:
            self.fields['role'].choices = [('User', 'User')]

    def save(self, commit=True):
        user = super().save(commit=False)
        selected_role = self.cleaned_data.get('role')

        if selected_role == 'Admin':
            user.is_superuser = True
            user.is_staff = True
        else:
            user.is_superuser = False
            user.is_staff = False

        if commit:
            user.save()
            group, created = Group.objects.get_or_create(name=selected_role)
            user.groups.add(group)
        
        return user

class AdminUserEditForm(forms.ModelForm):
    """
    Form for Admins/HR to EDIT an existing user.
    Does NOT include password fields.
    """
    ROLE_CHOICES = [
        ('User', 'User'),
        ('Hr', 'Hr'),
        ('Admin', 'Admin'),
    ]

    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-input'}))
    first_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))
    last_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-input'}))
    role = forms.ChoiceField(
        choices=ROLE_CHOICES, 
        required=True, 
        widget=forms.Select(attrs={'class': 'form-input'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'role']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input'}),
        }

    def __init__(self, *args, **kwargs):
        # Extract 'user' (the editor) from kwargs
        self.current_user = kwargs.pop('user', None)
        super(AdminUserEditForm, self).__init__(*args, **kwargs)
        
        # Apply CSS classes
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-input'

        # Set initial role based on instance status
        if self.instance.pk:
            if self.instance.is_superuser:
                self.fields['role'].initial = 'Admin'
            elif self.instance.groups.filter(name='Hr').exists():
                self.fields['role'].initial = 'Hr'
            else:
                self.fields['role'].initial = 'User'

        # --- ROLE RESTRICTION LOGIC ---
        # If the editor is NOT a superuser (i.e., they are HR), 
        # restrict them to only managing 'User' roles.
        if self.current_user and not self.current_user.is_superuser:
            self.fields['role'].choices = [('User', 'User')]

    def save(self, commit=True):
        user = super().save(commit=False)
        selected_role = self.cleaned_data.get('role')

        # Update Admin/Staff status
        if selected_role == 'Admin':
            user.is_superuser = True
            user.is_staff = True
        else:
            user.is_superuser = False
            user.is_staff = False

        if commit:
            user.save()
            # Update Groups: Clear old ones and set new one
            user.groups.clear()
            if selected_role != 'Admin':
                group, created = Group.objects.get_or_create(name=selected_role)
                user.groups.add(group)
        
        return user