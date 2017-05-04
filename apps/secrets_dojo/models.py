from __future__ import unicode_literals
from django.contrib import messages
from django.db import models
import re, bcrypt
from datetime import datetime, timedelta


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{3}$')
NAME_REGEX = re.compile(r'[a-zA-Z]{1,}')
USERNAME_REGEX = re.compile(r'[a-zA-Z0-9]{2,}')
# DATE_REGEX = re.compile(r'(\d{2})[/.-](\d{2})[/.-](\d{4})$')  #mm/dd/yyyy

class UserManager(models.Manager):
    def isValidRegistration(self, userInfo):
        passFlag = True
        errors = []

        # Check first_name
        if len(userInfo['first_name']) < 1:
            errors.append("First name field can't be blank!")
            passFlag = False
        if len(userInfo['first_name']) <3:
            errors.append("First name must contain at least 2 letters")
            passFlag = False
        if not NAME_REGEX.match(userInfo['first_name']):
            errors.append('First name must consist only of letters.')
            passFlag = False

        # Check last_name
        if len(userInfo['last_name']) < 1:
            errors.append("Last name field can't be blank!")
            passFlag = False
        if not NAME_REGEX.match(userInfo['last_name']):
            errors.append('Last name must consist only of letters.')
            passFlag = False

        # Check username
        if len(userInfo['username']) < 1:
            errors.append("username field can't be left blank!")
            passFlag = False
        if not USERNAME_REGEX.match(userInfo['username']):
            errors.append('Username must be at least 3 characters.')
            passFlag = False
        if len(self.filter(username=userInfo['username'])) > 0:  #Check to see username is not entered twice
            errors.append("Registration is invalid. Email already registered!")
            passFlag = False

        # Check email
        if len(userInfo['email']) < 1:
            errors.append("Email field can't be left blank!")
            passFlag = False
        if not EMAIL_REGEX.match(userInfo['email']) and len(userInfo['email']) > 1:
            errors.append("Invalid email. Please re-enter in <name>@<host>.com format")
            passFlag = False
        if len(self.filter(email=userInfo['email'])) > 0:  #Check to see email is not entered twice
            errors.append("Registration is invalid. Email already registered!")
            passFlag = False

        # Check date of birth
        try:
            dob = datetime.strptime(userInfo['dob'], '%m/%d/%Y')
            print(dob)
        except ValueError:
            errors.append("Invalid date of birth entered. Use mm/dd/YYYY")
            passFlag = False
        else:
            if datetime.now() < dob:
                errors.append("Can't enter a future birthdate")

        #Check Password
        if len(userInfo['password']) < 1:
            errors.append("Password field can't be blank.")
            passFlag = False
        if len(userInfo['password']) < 8:
            errors.append('Password must contain at least 8 characters.')
            passFlag = False
        if userInfo['password'] != userInfo['confirm_password']:
            errors.append('Passwords do not match.')
            passFlag = False
        if len(userInfo['password']) > 16:
            errors.append('Password must be 16 characters or less!')
            passFlag = False

        if passFlag == False:
            return (passFlag, errors)
        else:
            password = userInfo['password'].encode()
            pwhashed = bcrypt.hashpw(password, bcrypt.gensalt())
            new_user = self.create(first_name=userInfo['first_name'], last_name=userInfo['last_name'], username=userInfo['username'], email=userInfo['email'], password = pwhashed, dob=dob)
            return (passFlag, new_user)


    def ValidLogin(self, userInfo):
        passFlag = True
        errorsList = []

    #    user = User.userManager.filter(email = userInfo['email'])
    #     if len(userInfo['email']) < 1:
    #        errors.append("Cannot leave email field blank!")
    #     if len(user) > 0:
    #         hashed = User.objects.get(email = userInfo['email']).password.encode('utf-8')
    #         password = userInfo['password'].encode('utf-8')
    #         if bcrypt.hashpw(password, hashed) == hashed:
    #             passFlag = True
    #         else:
    #             errors.append("Incorrect login credentials. Please try again")
    #             passFlag = False
    #     else:
    #         errors.append("Unsuccessful login.")
    #         passFlag = False
    #     return [passFlag, errors]


        if len(userInfo['username']) < 1:
            errorsList.append("Username field Cannot field blank!")

        if len(userInfo['password']) < 1:
            errorsList.append("Cannot leave password field blank!")
        # the_user = User.objects.filter(email=email)  #grabs user filtered by email
        the_user = User.objects.filter(username=userInfo['username'])  #grabs user filtered by username, puts all the users that it finds with this username into a list.
        # so the user you're looking for, if you get only get one back, is at index 0
        if len(the_user) > 0:
            hashed = User.objects.get(username = userInfo['username']).password.encode('utf-8')
            password = userInfo['password'].encode('utf-8')
            if bcrypt.hashpw(password, hashed) == hashed:
                passFlag = True
                return (passFlag, the_user[0])
            else:
                errorsList.append("Incorrect login credentials. Ensure that your username and password is correct. Please try again")
                passFlag = False
        else:
            errorsList.append("Unsuccessful login.")
            passFlag = False
        return (passFlag, errorsList)

class User(models.Model):
    first_name = models.CharField(max_length=200, null=True)
    last_name = models.CharField(max_length=200, null=True)
    username = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=255, null=True)
    password = models.CharField(max_length=200)
    dob = models.DateField(null=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class SecretManager(models.Manager):
    def validate(self, postSecret):
        if len(postSecret) < 1:
            return {'error': 'False'}
        else:
            return {"secret": postSecret}
    def addlike(self, secretid, userid):
        if len(self.filter(id = secretid).filter(likedby__id = userid)) > 0:
            return {'errors': 'You already liked this!!'}
        else:
            this_secret = Secret.objects.get(id = secretid)
            this_user = User.objects.get(id = userid)
            this_secret.likedby.add(this_user)
            return {}

class Secret(models.Model):
    content = models.CharField(max_length=255)
    creator = models.ForeignKey(User)
    likes = models.IntegerField(default=0)    #???
    likedby = models.ManyToManyField(User, related_name ="likedusers", default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = SecretManager()
