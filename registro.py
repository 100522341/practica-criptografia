
import json

"""Funciones para gestionar el archivo json de base de datos"""

def load_users():
    """Función que devuelve un diccionario con TODOS los usuarios de la base de datos (json) """
    pass

def save_users(users):
    """Función que almacena el diccionario users en la base de datos json"""
    if not isinstance(users, dict):
        raise TypeError("users debe ser un diccionario")
    # Con el modo "w", sobrescribimos el json cada vez con el dict users, no añadimos nada nuevo
    with open("database.json", "w") as file:
        json.dump(users, file, indent = 4, sort_keys = True)

def register_user(username, password):
    """Función que registra un usuario, para lo que: Comprueba si el usuario ya existe Hashea la contraseña. Añade el usuario al diccionario y llama a save_users. Devuelve un mensaje de éxito o error."""
    pass

def authenticate_user(username, password):
    """Función que verifica que el usuario que accede al sistema es quien dice ser. Se admitirá el acceso SI Y SOLO SI el username existe en el JSON y si la contraseña introducida coincide con la registrada."""
    pass

def get_user(username):
    """Función (OPCIONAL) que devuelve la información de un usuario"""
    pass