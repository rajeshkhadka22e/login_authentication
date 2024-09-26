from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),  # Updated the path name here
    path('logout/', views.handlelogout, name='logout'), 
    path('activate/<uidb64>/<token>', views.ActivateAccountView.as_view(), name='activate'),
    # Assuming you have an index view
    path('request-reset-email/',views.RequestResetEmailView.as_view(),name='request-reset-email'),
    path('set-new-password/<uidb64>/<token>',views.SetNewPasswordView.as_view(),name='set-new-password'),
]
