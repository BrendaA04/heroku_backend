import fastapi
import sqlite3
import random
import hashlib
import datetime
from fastapi import Depends
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware

# Crea la base de datos
conn = sqlite3.connect("contactos.db")

app = fastapi.FastAPI()
securityBearer = HTTPBearer()

origins = [
    "http://127.0.0.1:5000",
    "https://herok-frontend-a476fdd3e0e6.herokuapp.com",
    "*"  # Asegúrate de definir correctamente tus orígenes permitidos
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Contacto(BaseModel):
    email: str
    nombre: str
    telefono: str

def obtener_usuario(credentials: HTTPBearer = Depends()):
    """Obtiene el usuario a partir de las credenciales del token."""
    token = credentials.credentials
    connx = sqlite3.connect("usuarios.db")
    c = connx.cursor()
    c.execute('SELECT token FROM usuarios WHERE token = ?', (token,))
    existe = c.fetchone()
    if existe is None:
        raise fastapi.HTTPException(status_code=401, detail="Token Inexistente")
    return existe

@app.post("/contactos")
async def crear_contacto(contacto: Contacto, credentials: HTTPBearer = Depends(securityBearer)):
    """Crea un nuevo contacto."""
    usuario = obtener_usuario(credentials)
    c = conn.cursor()

    c.execute('SELECT * FROM contactos WHERE email = ?', (contacto.email,))
    existe = c.fetchone()

    if existe is not None:
        raise fastapi.HTTPException(status_code=400, detail="Contacto ya existe")
    else:
        c.execute('INSERT INTO contactos (email, nombre, telefono) VALUES (?, ?, ?)',
                  (contacto.email, contacto.nombre, contacto.telefono))
        conn.commit()
        return contacto

@app.get("/contactos")
async def obtener_contactos(credentials: HTTPBearer = Depends(securityBearer)):
    """Obtiene todos los contactos."""
    obtener_usuario(credentials)  # Verifica la autenticación
    c = conn.cursor()
    c.execute('SELECT * FROM contactos;')
    response = [{"email": row[0], "nombre": row[1], "telefono": row[2]} for row in c]
    return response

@app.get("/contactos/{email}")
async def obtener_contacto(email: str, credentials: HTTPBearer = Depends(securityBearer)):
    """Obtiene un contacto por su email."""
    obtener_usuario(credentials)  # Verifica la autenticación
    c = conn.cursor()
    c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
    contacto = [{"email": row[0], "nombre": row[1], "telefono": row[2]} for row in c]
    
    if not contacto:
        raise fastapi.HTTPException(status_code=404, detail="Contacto no encontrado")

    return contacto[0]

@app.put("/contactos/{email}")
async def actualizar_contacto(email: str, contacto: Contacto, credentials: HTTPBearer = Depends(securityBearer)):
    """Actualiza un contacto."""
    obtener_usuario(credentials)  # Verifica la autenticación
    c = conn.cursor()

    c.execute('SELECT * FROM contactos WHERE email = ?', (contacto.email,))
    existe = c.fetchone()

    if existe is None:
        raise fastapi.HTTPException(status_code=400, detail="Contacto no existe")
    else:
        c.execute('UPDATE contactos SET nombre = ?, telefono = ? WHERE email = ?',
                  (contacto.nombre, contacto.telefono, email))
        conn.commit()
        return contacto

@app.delete("/contactos/{email}")
async def eliminar_contacto(email: str, credentials: HTTPBearer = Depends(securityBearer)):
    """Elimina un contacto."""
    obtener_usuario(credentials)  # Verifica la autenticación
    c = conn.cursor()

    c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
    existe = c.fetchone()

    if existe is None:
        raise fastapi.HTTPException(status_code=400, detail="Contacto no existe")
    else:
        c.execute('DELETE FROM contactos WHERE email = ?', (email,))
        conn.commit()
        return {"mensaje": "Contacto eliminado"}

@app.get("/")
def auth(credentials: HTTPBearer = Depends(securityBearer)):
    """Autenticación"""
    obtener_usuario(credentials)  # Verifica la autenticación
    return {"mensaje": "Token Valido"}

security = HTTPBasic()
@app.get("/token")  # Endpoint para obtener token
def validate_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Validación de usuario"""
    connx = sqlite3.connect("usuarios.db")
    username = credentials.username
    password = credentials.password
    hashpassword = hashlib.sha256(password.encode()).hexdigest()
    c = connx.cursor()

    hora_actual = datetime.datetime.now()
    hora_actual_formateada = hora_actual.strftime("%H:%M")

    caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()=+-*/@#$%&!?'
    longitud = 8
    token = ''
    for i in range(longitud):
        token += random.choice(caracteres)

    hashtoken = hashlib.sha256(token.encode()).hexdigest()
    c.execute('UPDATE usuarios SET token = ?, timestamp = ? WHERE correo = ? AND password = ?',
              (hashtoken, hora_actual_formateada, username, hashpassword))
    connx.commit()

    c.execute('SELECT token FROM usuarios WHERE correo = ? AND password = ?', (username, hashpassword))
    existe = c.fetchone()
    
    if existe is None:
        raise fastapi.HTTPException(status_code=401, detail="No autorizado")

    token = existe[0]
    return {"token": token}
