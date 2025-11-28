from fastapi import FastAPI

from sqladmin import Admin, ModelView

from models.users import UsersOrm


class UserAdminView(ModelView, model = UsersOrm):
    can_create = True
    column_list = ('id', 'username' 'email', 'avatar_links')
    form_columns = ('id', 'username' 'email', 'avatar_links')


def setup_admin(app: FastAPI, engine):
    admin = Admin(app, engine, title='Admin panel')
    admin.add_view(UserAdminView)
