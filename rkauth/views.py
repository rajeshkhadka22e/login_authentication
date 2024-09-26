from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.views.generic import View


#to activae the user account


from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError

#reset password generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

#threading
import threading
class EmailThread(threading.Thread):
    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self) 

    def run(self):
        self.email_message.send()



#gettings token from utils.py
from .utils import TokenGenerator,generate_token  # Ensure the correct TokenGenerator class is used




#email
from django.core.mail import send_mail,EmailMultiAlternatives,EmailMessage
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings





def signup(request):
    if request.method == "POST":
        # Get form data
        username = request.POST.get('username')
     
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')

        # Print form data for debugging (optional)
        print(f"Signup data - Username: {username}, Password1: {pass1}, Password2: {pass2}")

        # Validation - Username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists! Please choose another one.")
            return render(request, 'auth/signup.html', {'username': username,  'email': email})

        # Validation - Email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists! Please use another email.")
            return render(request, 'auth/signup.html', {'username': username, 'email': email})

        # Validation - Username length
        if len(username) > 10:
            messages.error(request, "Username must be under 10 characters.")
            return render(request, 'auth/signup.html', {'username': username, 'email': email})

        # Validation - Passwords do not match
        if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'auth/signup.html', {'username': username, 'email': email})

        # Validation - Username must be alphanumeric
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric.")
            return render(request, 'auth/signup.html', {'username': username,  'email': email})

        # Create the user with hashed password
        user = User.objects.create_user(username=username, password=pass1, email=email)
        user.is_active=False
        user.save()
        current_site = get_current_site(request)
        email_subject = "Activate your account"
        message = render_to_string('auth/activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000/'.domain,  # Changed from hardcoded to dynamic domain
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        # Corrected EmailMessage instantiation
        email_message = EmailMessage(
            email_subject,  # Subject
            message,  # Email body
            settings.EMAIL_HOST_USER,  # Changed from message.settings.EMAIL_HOST_USER to settings.EMAIL_HOST_USER
            [email],  # Recipient email
        )

        EmailThread(email_message).start()

        # Success message and redirect to login
        messages.success(request, "Account created successfully! Please activate your account by clicking on the email link.")

        return redirect('login')

    # Render signup page if the request method is not POST
    return render(request, 'auth/signup.html')





class ActivateAccountView(View):
    def get(self,request,uid64,token):
        try:
            uid= force_str(urlsafe_base64_decode())
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None

        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activate Successfully")
            return redirect('rkauth/login')
        
        return render(request,"auth/activatefail.html")






def login(request):
    if request.method == "POST":
        # Get form data
        username = request.POST.get('username')
        pass1 = request.POST.get('pass1')

        # Print login data for debugging (optional)
        print(f"Login data - Username: {username}, Password: {pass1}")

        # Authenticate user credentials
        user = authenticate(username=username, password=pass1)

        # If user is authenticated, log them in
        if user is not None:
            auth_login(request, user)
            return redirect('/')  # Redirect to the index page after login
        else:
            # Invalid credentials, show error message and render login page with username retained
            messages.error(request, "Bad credentials! Please try again.")
            return render(request, 'auth/login.html', {'username': username})

    # Render login page if the request method is not POST
    return render(request, 'auth/login.html')

def handlelogout(request):
    logout(request)
    messages.success(request, "Logout successful")
    return redirect('login')  # Replace 'login' with the name of your URL pattern for the login page



class RequestResetEmailView(View):
    def get(self, request):
        return render(request, "auth/request-reset-email.html")
    

    def post(self,request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email)


        if user.exists():
            current_site = get_current_site(request)
            email_subject = '[Reset password]'
            message = render_to_string('auth/reset-user-password.html',
            {
             'user': user,
            'domain': '127.0.0.1:8000',  # Changed from hardcoded to dynamic domain
            'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
            'token': PasswordResetTokenGenerator().make_token(user[0])   
            })

            email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,
            [email],  # Recipient email
        )

        EmailThread(email_message).start()

        messages.info(request,'WE have sent you an email with instruction how to reset the password ')
        return render(request,'auth/request-reset-email.html')
    


class SetNewPasswordView(View):
    def get(self, request,uidb64,token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset Link Invalid")
                return render(request, "auth/request-reset.email.html")
        except DjangoUnicodeDecodeError as identifier:
            pass
        
        return render(request,"auth/set-new-password.html",context)

    def post(self,request,uidb64,token):
        context ={
            'uidb64':uidb64,
            'token':token
        }
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'auth/set-new-password.html')

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(pass1)
            user.save()
            messages.success(request,"Password Reset successfull Please login with new password")
            return redirect("auth/login")
   
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,"somthings went wrong")
            return render(request, 'auth/set-new-password.html',context)
        

        return render(request,'auth/set-new-password.html',context)
