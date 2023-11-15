import fastapi
from fastapi import HTTPException
import sqlite3
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Crea la base de datos
conn = sqlite3.connect("sql/contactos.db")

app = fastapi.FastAPI()

origins = [
    "http://127.0.0.1:5000",
    "https://contactos-frond-5ed01e72bbb6.herokuapp.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Contacto(BaseModel):
    email : str
    nombre : str
    telefono : str

@app.get("/contactos")
async def obtener_contactos():
    """Obtiene todos los contactos."""
    # DONE Consulta todos los contactos de la base de datos y los envia en un JSON
    c = conn.cursor()
    c.execute('SELECT * FROM contactos')
    response = []
    for row in c:
        contacto = {"email":row[0], "nombre":row[1], "telefono":row[2]}
        response.append(contacto)
    return response
@app.post("/contactos")
async def crear_contacto(contacto: Contacto):
    try:
        # Insertar el contacto en la base de datos
        c = conn.cursor()
        c.execute('INSERT INTO contactos (email, nombre, telefono) VALUES (?, ?, ?)',
                  (contacto.email, contacto.nombre, contacto.telefono))
        conn.commit()
        
        

        # Responder con un mensaje de éxito
        return {"message": "Contacto guardado"}
    except Exception as e:
        # En caso de error, responder con un mensaje de error
        return HTTPException(status_code=500, detail="Error al ingresar el contacto")
@app.get("/contactos/{email}")
async def obtener_contacto(email: str):
    """Obtiene un contacto por su email."""
    # Consulta el contacto por su email
    c = conn.cursor()
    c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
    contacto = None
    for row in c:
        contacto = {"email":row[0],"nombre":row[1],"telefono":row[2]}
    return contacto


@app.put("/contactos/{email}")
async def actualizar_contacto(email: str, contacto: Contacto):
    """Actualiza un contacto."""
    # TODO Actualiza el contacto en la base de datos
    c = conn.cursor()
    c.execute('UPDATE contactos SET nombre = ?, telefono = ? WHERE email = ?',
              (contacto.nombre, contacto.telefono, email))
    conn.commit()
    return contacto


@app.delete("/contactos/{email}")
async def eliminar_contacto(email: str):
    """Elimina un contacto."""
    # TODO Elimina el contacto de la base de datos
    c = conn.cursor()
    c.execute('DELETE FROM contactos WHERE email = ?', (email,))
    conn.commit()
    return {"mensaje":"Contacto eliminado"}