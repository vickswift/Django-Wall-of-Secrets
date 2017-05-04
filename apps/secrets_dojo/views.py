from django.shortcuts import render, redirect
from .models import User, Secret
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.db.models import Count

# User login page. if user already logged in, gets redirected to secrets page
def index(request):
    if "id" in request.session:
        request.session['logged_in'] = True
        # return redirect(reverse('secrets'))
        return redirect('/secrets')
    return render(request, 'secrets_dojo/index.html')

# this part processes the submitted registration
def process_registration(request):
    if request.method != "POST":
        return redirect(reverse('index'))
    else:
        user_info = User.objects.isValidRegistration(request.POST)
        if user_info[0]:  # same as saying if user_info[0] == True
            request.session['id'] = user_info[1].id
            print ("got session id", request.session['id'])
            return redirect(reverse('secrets'))
        else:
            for error_message in user_info[1]:
                messages.error(request, error_message)
            return redirect(reverse('index'))

# this logs in the user
def login(request):
    if request.method != "POST":
        return redirect(reverse('index'))
    else:
        user_info = User.objects.ValidLogin(request.POST)
        if user_info[0] == True:
            # request.session['logged_in']
            request.session['id'] = user_info[1].id


            return redirect(reverse('secrets'))
        else:
            for error_message in user_info[1]:
                messages.error(request, error_message)
            return redirect(reverse('index'))

#Take us to the secrets page
def secrets(request):
    if "id" not in request.session:
        request.session['logged_in'] = False
        messages.warning(request, "User not found.")
        return redirect(reverse('index'))  #Same as 'return redirect('/')'
    else:
        context = {
        'users': User.objects.all(),
        'user': User.objects.get(id=request.session["id"]),
        'postedsecrets': Secret.objects.annotate(count=(Count('likedby'))).order_by('-created_at')[:5]
    }
    return render(request, 'secrets_dojo/secrets.html', context)

def mostpopularsecrets(request):
    if 'id' not in request.session:
        messages.error(request, 'Nice try, log in or register.')
        return redirect(reverse('index'))

    secrets = Secret.objects.annotate(count=(Count('likedby'))).order_by('-count')
    context = {
        'mostpop': secrets,
        'user': User.objects.get(id=request.session['id']),
    }
    return render(request, 'secrets_dojo/mostpopular.html', context)

def likesecret(request,word, secretid):
    if request.method == "GET":
        return redirect(reverse('index'))

    secret = Secret.objects.addlike(secretid, request.session['id'])
    if 'errors' in secret:
        messages.error(request, secret['errors'])
    if word == "sec":
        return redirect(reverse('secrets'))
        # return redirect('/secrets')
    else:
        return redirect(reverse('mostpopularsecrets'))

def deletesecret(request,word, id):
    if request.method == "GET":
        messages.error(request, 'Nice try, log in or register.')
        return redirect(reverse('index'))

    Secret.objects.filter(id=id).delete()
    if word == "pop":
        return redirect(reverse('mostpopularsecrets'))
    else:
        return redirect(reverse('secrets'))


def postsecret(request):
    if 'id' not in request.session:
        messages.error(request, 'Nice try, log in or register.')
        return redirect(reverse('index'))

    secret = Secret.objects.validate(request.POST['makesecret'])
    if 'error' in secret:
        messages.error(request, "Secret field must not be blank")
        return redirect(reverse('secrets'))
    else:
        Secret.objects.create(content = request.POST['makesecret'], creator = User.objects.get(id=request.session['id'])) #Create a secret linked to a user
        return redirect(reverse('secrets'))

def delete_user(request, id):
    if 'id' not in request.session:
        messages.error(request, 'Nice try, log in or register.')
        return redirect(reverse('index'))
    User.objects.filter(id=id).delete()
    return redirect(reverse('logout'))

#Error Handling. Catch any unwanted alphanumerics
def any(request):
    messages.error(request, 'Nice try.')
    return redirect('/')

# this logs out the user
def logout(request):
    request.session.clear()
    return redirect (reverse('index'))
