import werkzeug
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor , CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL","sqlite:///blog_relational_final.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#configure application that uses flask-login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return None

#create wtf form
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign me up!')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Let Me In!')

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment")
    submit = SubmitField("Submit Comment")

##CONFIGURE TABLES
class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)

    #act like list of blogposts , post is the property in blogpost class
    posts = relationship('BlogPost', back_populates = 'author')

    #act like list of comments, comments is the property in comment class
    comments = relationship('Comment', back_populates = 'comment_author')
db.create_all()

class BlogPost(UserMixin,db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #create foreign key , user.id
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    #create reference to the User object, author is the property in the User class
    author = relationship('User', back_populates='posts')

    #act like list of comments, comments is the property of comment class
    comments = relationship('Comment', back_populates = 'parent_post')
db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
    text = db.Column(db.Text, nullable=False)

    #create a foreign key for user class
    author_id = db.Column(db.Integer, ForeignKey('user.id'))
    #create reference to the User object
    comment_author = relationship('User', back_populates = 'comments')

    #create a foreign key for the blogpost class
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    #create a reference to the blogpost object
    parent_post = relationship('BlogPost', back_populates = 'comments')
db.create_all()


admin = User.query.get(1)

#admin only decorator function
def admin_only(func):
    @wraps(func)
    def decorator_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id !=1:
            return abort(403)
        return func(*args, **kwargs)
    return decorator_function


#create gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods = ["POST","GET"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():

        user = User.query.filter_by(email = form.email.data).first()
        if user:
            flash('You have already signed up for that email, log in instead!')
            return redirect(url_for('login'))

        else:
            hash_password = werkzeug.security.generate_password_hash(password=form.password.data, method='pbkdf2:sha256',
                                                                 salt_length=8)
            new_user = User(
                name = form.name.data,
                email = form.email.data,
                password = hash_password
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            return redirect(url_for('get_all_posts'))


    return render_template("register.html",form = form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        # check the user by email
        user = User.query.filter_by(email = form.email.data).first()


        #check the password
        if user:
            match_password = werkzeug.security.check_password_hash(user.password, form.password.data)

            if match_password:
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else :
                flash('Password incorrect ,please try again.')
                return redirect(url_for('login'))
        else:
            flash('Email does not exist, please try again.')
            return redirect(url_for('login'))
    return render_template("login.html", form = form )


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["GET","POST"])

def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('For comment you must log in!')
            return redirect(url_for('login'))
        new_comment = Comment(
            text = form.comment.data,
            comment_author = current_user,
            parent_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post,form = form, current_user = current_user, gravatar = gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET","POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
