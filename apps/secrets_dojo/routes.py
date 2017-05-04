from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name = 'index'),
    url(r'^registration$', views.process_registration, name = 'process_registration'),
    url(r'^login$', views.login, name = 'login'),
    # url(r'^success$', views.success, name='success'),
    url(r'^secrets$', views.secrets, name='secrets'),
    url(r'^postsecret$', views.postsecret, name='postsecret'),
    url(r'^mostpopularsecrets$', views.mostpopularsecrets, name='mostpopularsecrets'),
    url(r'^likesecret/(?P<word>\w+)/(?P<secretid>\d+)$', views.likesecret, name="likesecret"),
    url(r'^deletesecret/(?P<word>\w+)/(?P<id>\d+)$', views.deletesecret, name="deletesecret"),
    url(r'^delete/(?P<id>\d+)$', views.delete_user, name="delete"),
    url(r'^logout$', views.logout, name = 'logout'),
    url(r'^', views.index, name = 'login_index'),
    url(r'^.+$', views.any, name="any"),
]
