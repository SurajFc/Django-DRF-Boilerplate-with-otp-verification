# Django-DRF-BoilerPlate-with-OTP-Verification
The is simple DRF boilerplate with user registeration features with otp verification 


API Endpoints:-
1. http://127.0.0.1:8000/register       #for Regiteration
2. http://127.0.0.1:8000/verify         #verify OTP
3. http://127.0.0.1:8000/login          #for Login also generate JSONWebToken    
4. http://127.0.0.1:8000/forgot         #a mail will be send with a auto generated password
5. http://127.0.0.1:8000/reset          #for reseting your password after login


JWT Authentication:-
use this in headers for authentication==> JWT "your token" 


Add your email id and password in settings.py before starting. Also change the Secret Key value.
then..
1. python manage.py makemigrations
2. python manage.py migrate
3. python manage.py runserver

Thanks...
