#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import jinja2

import os
import re

import random
import hashlib
import hmac
import string

import json

import time
from datetime import datetime, timedelta

from google.appengine.ext import db
from google.appengine.api import memcache

# frontpage hello world
class MainHandler(webapp2.RequestHandler):
  def get(self):
    self.response.write('Hello, world!')

#---------------------------------------------#
#         LOAD AND RENDER TEMPLATES           #
#               SET COOKIES                   #
#---------------------------------------------#

#create jinja environment and load it
jinja_environment = jinja2.Environment(autoescape=True,
  loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

# render html template
def render_str(template, **params):
  t = jinja_environment.get_template(template)
  return t.render(params)

# jinja2 filter to preserve new lines on posts
def nl2br(value):
  return value.replace('\n','<br>\n')
  
jinja_environment.filters['nl2br'] = nl2br

class BaseHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.write(*a, **kw)

  def render_str(self, template, **params):
    params['user'] = self.user
    return render_str(template, **params)
  
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def render_json(self, d):
    json_txt = json.dumps(d)
    self.response.headers['Content-Type'] = 'application/json;'
    self.write(json_txt)

  def set_cookie(self, name, value):
    cookie_value = match_pair(value)
    self.response.headers.add_header(
      'Set-Cookie',
      '%s=%s; Path=/' % (name, cookie_value))

  def read_cookie(self, name):
    cookie_value = self.request.cookies.get(name)
    return cookie_value and check_pair(cookie_value)

  def login_set_cookie(self, user):
    self.set_cookie('user_id', str(user.key().id()))

  def logout(self):
    self.response.headers.add_header(
      'Set-Cookie',
      'user_id=; Path=/')

  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    uid = self.read_cookie('user_id')
    self.user = uid and User.by_id(int(uid))

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'

#---------------------------------------------#
#                  HELPERS                    #
#---------------------------------------------#

secret = "the_secret!"

def match_pair(value):
  #returns pair value|hashed value
  return "%s|%s" % (value, hmac.new(secret, value).hexdigest())

def check_pair(pair):
  #checks if entered pair corresponds to previously matched pair
  value = pair.split('|')[0]
  if pair == match_pair(value):
    return value

def make_salt(length = 5):
  return "".join(random.choice(string.ascii_letters) for x in range(length))

def make_pw_hash(name, pw, salt = None):
  # hash pw with salt to store in db
  if not salt:
    salt = make_salt()
  h = hashlib.sha256(name + pw + salt).hexdigest()
  return "%s,%s" % (salt, h)

def valid_pw(name, pw, h):
  #check values against stored hashed value
  salt = h.split(',')[0]
  return h == make_pw_hash(name, pw, salt)

# memcache

def age_set(key, val):
  save_time = datetime.utcnow()
  memcache.set(key, (val, save_time))

def age_get(key):
  r = memcache.get(key)
  if r:
    val, save_time = r
    age = (datetime.utcnow() - save_time).total_seconds()
  else:
    val, age = None, 0
  return val, age

def add_post(post):
  post.put()
  time.sleep(0.1)
  front_posts(update = True)
  return str(post.key().id())

def front_posts(update = False):
  mc_key = "frontpage"
  posts, age = age_get(mc_key)

  if update or posts is None:
    posts = db.GqlQuery("select * from Post order by created desc limit 10")
    posts = list(posts)
    age_set(mc_key, posts)
  return posts, age

def age_str(age):
  s = "Queried %s seconds ago"
  age = int(age)

  if age == 1:
    s = s.replace("seconds", "second")
  return s % age

def blog_flush():
  memcache.flush_all()

#---------------------------------------------#
#                   USER                      #
#---------------------------------------------#
# users parent key
def user_parent_key(group = 'default'):
  return db.Key.from_path('users', group)

class User(db.Model):
  """set user properties"""
  name = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  email = db.StringProperty()

  @classmethod
  def by_id(cls, uid):
    """get user id"""
    return cls.get_by_id(uid, parent = user_parent_key())

  @classmethod
  def by_name(cls, name):
    """retrieves username by querying db"""
    u = cls.all().filter('name =', name).get()
    return u

  @classmethod
  def register(cls, name, pw, email = None):
    """hash pw and store on db"""
    pw_hash = make_pw_hash(name, pw)
    return User(parent = user_parent_key(), name = name, pw_hash = pw_hash, email = email)

  @classmethod
  def login(cls, name, pw):
    """checks if username and pw match and are valid"""
    u = cls.by_name(name)
    if u and valid_pw(name, pw, u.pw_hash):
      return u

#---------------------------------------------#
#                   SIGNUP                    #
#---------------------------------------------#

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
  return USER_RE.match(username)

def valid_pwd(password):
  return PWD_RE.match(password)

def valid_email(email):
  return not email or EMAIL_RE.match(email)

class SignUp(BaseHandler):
  def get(self):
    self.render('signup.html')

  def post(self):
    has_error = False
    self.username = self.request.get("username")
    self.password = self.request.get("password")
    self.verify = self.request.get("verify") 
    self.email = self.request.get("email")

    params = dict(username = self.username,
      email = self.email)

    if not valid_username(self.username):
      params['usernameError'] = "Enter a valid username."
      has_error = True

    if not valid_pwd(self.password):
      params['passwordError'] = "Enter a valid password."
      has_error = True
    elif self.password != self.verify:
      params['verifyError'] = "Your passwords didn't match."
      has_error = True

    if not valid_email(self.email):
      params['emailError'] = "If you are going to use your email, please enter a valid one."
      has_error = True

    if has_error:
      self.render('signup.html', **params)

    else:
      self.done()

    def done(self, *a, **kw):
      raise NotImplementedError

class Register(SignUp):
  def done(self):
    un = User.by_name(self.username)
    if un:
      msg = "Username already exists. Please, choose another one."
      self.render('signup.html', usernameError = msg)
    else:
      # self.render('signup.html', usernameError = "New registrations are not available.")
      un = User.register(self.username, self.password, self.email)
      un.put()
      front_posts(True)
      self.login_set_cookie(un)
      self.redirect('/blog/welcome')

class Welcome(BaseHandler):
  def get(self):
    if self.user:
      self.render('welcome.html', username = self.user.name)
    else:
      self.redirect('/signup')

#---------------------------------------------#
#              LOGIN AND LOGOUT               #
#---------------------------------------------#

class Login(BaseHandler):
  def get(self):
    self.render('login.html')

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')

    un = User.login(username, password)

    if un:
      self.login_set_cookie(un)
      self.redirect('/blog/welcome')
    else:
      msg = "Invalid username or password."
      self.render('login.html', error = msg)

class Logout(BaseHandler):
  def get(self):
    self.logout()
    self.redirect('/blog/signup')

#---------------------------------------------#
#                   BLOG                      #
#---------------------------------------------#

# create parent to blog entities to ensure strong consistency
def parent_key(name = 'default'):
  return db.Key.from_path('blogs', name)

class Post(db.Model):
  """define and render single post"""
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  modified = db.DateTimeProperty(auto_now = True)
  author = db.StringProperty()

  def render(self):
    self.render('post.html', post=self)

  def as_dict(self):
    time_format = '%c'
    d = {'subject': self.subject,
        'content': self.content,
        'author': self.author,
        'created': self.created.strftime(time_format),
        'last_modified': self.modified.strftime(time_format)}
    return d

class NewPostForm(BaseHandler):
  """render form to post if valid user is logged in"""
  def get(self):
    if self.user:
      self.render('newpost.html')
    else:
      self.redirect('/login')

  def post(self):
    has_error = False
    subject = self.request.get("subject")
    content = self.request.get("content")
    author = self.user.name

    params = dict(subjet = subject,
      content = content, author = author)

    if not subject:
      params['error_title'] = "A post needs a title."
      has_error = True

    if not content:
      params['error_content'] = "A post needs content."
      has_error = True

    if has_error:
      self.render('newpost.html', **params)
    else: 
      post = Post(parent = parent_key(), content = content, subject = subject, author = author)
      add_post(post)
      self.redirect('/blog/%s' % str(post.key().id()))

class Permalink(BaseHandler):
  """retrieves post id, inserts into db and generates url"""
  def get(self, post_id):    
    post_key = 'POST_' + post_id
    post, age = age_get(post_key)

    if not post:
      #Key.from_path(kind, id_or_name, parent=None, namespace=None)
      key = db.Key.from_path('Post', int(post_id), parent =  parent_key())
      post = db.get(key)
      age_set(post_key, post)
      age = 0

    if self.format == 'html':
      self.render('post.html', post = post, age = age_str(age))
    else:
      self.render_json(post.as_dict())

class BlogHome(BaseHandler):
  """gets posts from db and render index"""
  def get(self):
    posts, age = front_posts()
    if self.format == 'html':
      self.render('index.html', posts = posts, age = age_str(age))
    else:
      return self.render_json([post.as_dict() for post in posts])

class FlushHandler(BaseHandler):
  def get(self):
    blog_flush()
    self.redirect('/blog')

#---------------------------------------------#
#                   URLs                      #
#---------------------------------------------#

app = webapp2.WSGIApplication([
  ('/', MainHandler),
  ('/blog/signup', Register),
  ('/blog/welcome/?', Welcome),
  ('/blog/?(?:\.json)?', BlogHome),
  ('/blog/(\d+)(?:\.json)?', Permalink),
  ('/blog/newpost/?', NewPostForm),
  ('/login', Login),
  ('/logout', Logout),
  ('/blog/flush', FlushHandler)
  ], debug=True)
