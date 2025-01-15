#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def authenticate_user():
    pass

class Signup(Resource):
    def post(self):
        try:
            data = request.get_json()
            user = User(
                username=data['username'],
                image_url=data['image_url'],
                bio=data['bio']
            )
            user.password_hash=data['password']
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return make_response(user.to_dict(only=('id','username','image_url','bio')), 201)
        except Exception as e:
            return make_response(
                {"errors": e.args},
                422
            )

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id != None:
            user = User.query.filter(User.id == user_id).first()
            if user:
                return make_response(user.to_dict(only=('id','username','image_url','bio')), 200)
        return make_response({"errors":"User not logged in"}, 401)
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter(User.username == data['username']).first()
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return make_response(user.to_dict(only=('id','username','image_url','bio')), 200)
        return make_response({"errors": ["Login Error"]}, 401)

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id != None:
            session['user_id'] = None
            return make_response("", 204)
        return make_response({"errors":"User not logged in"}, 401)
        

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id == None:
            return make_response({"errors":"User not logged in"}, 401)
        recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
        return make_response(recipes, 200)
    
    def post(self):
        user_id = session.get('user_id')
        if user_id == None:
            return make_response({"errors":"User not logged in"}, 401)
        try:
            data = request.get_json()
            recipe = Recipe(
                user_id=user_id,
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete']
            )
            db.session.add(recipe)
            db.session.commit()
            return make_response(recipe.to_dict(), 201)
        except Exception as e:
            return make_response({"errors": [e.args]}, 422)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)