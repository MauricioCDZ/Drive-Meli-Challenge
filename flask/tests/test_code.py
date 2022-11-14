import unittest
from app import app
import io
import json
import os
import time
import requests
from pathlib import Path
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import mysql.connector
from googleapiclient.http import MediaFileUpload

class TestFileUpload(unittest.TestCase):
    # Test para probar que el usuario pueda acceder a la ruta login.
    def test_get_login(self):
      
        client = app.test_client()
        
        # Execute / Act
        response = client.get('/')
      
        assert response.data == b"Hello Welcome to the MELI Challenge  <a href='/login'><button>Login</button></a>"


    # Test upload drive:
    # Test para probar que cuando un archivo se sube a la cuenta de Drive y el usuario vista la ruta /updatefiles
    # este se guarda en la base de datos. 
    # Esta prueba analiza el correcto funcionamiento de las funciones def update_files(),   
    # fetch_changes() 
    def test_upload_drive(self):

        # Conectarse la base de datos
        connection = mysql.connector.connect(
        user='root',password='root',host='mysql',port=3306,database='db'
        )

        cursor= connection.cursor()

      
        SCOPES = ['https://www.googleapis.com/auth/drive','https://mail.google.com/']
        client = app.test_client()
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        service_drive = build('drive', 'v3', credentials=creds)
        # Nombre del archivo
        file_metadata = {'name':'archivotest.png'}
        media = MediaFileUpload('tests/archivotest.png', mimetype='image/png')
        # Se sube el archivo al Drive y se obtiene su Id para compararlo con el que se 
        # almacena en la base de datos
        file = service_drive.files().create(body=file_metadata, media_body=media, fields='id').execute()
        file_uploaded_file = file.get("id")

        # Se simula la vista del usuario a la ruta /updatefilfes
        requests.get('http://localhost:5000/updatefiles')
        cursor.execute('Select * FROM Drivefile')
        driveFiles = cursor.fetchall()
        # Se obtiene los archivos de la base de datos
        
     
       

        flag_db = False
        # Se busca entre los archivos de la base de datos uno que tenga el mismo Id al del archivo que se acabo de subir.
        for filedrive in driveFiles:
            if filedrive[1] == file_uploaded_file:
                # Si se encuentra se coloca una bandera en True
                flag_db = True
        
        assert flag_db == True

    # Test para probar el cambio de privacidad de publico a privado.
    # Para ello se sube un archivo, se comprueba que primeramente en la base de datos queda con acceso Publico
    # debido a la desincronizacion (explicado anteriormente) y luego de visitar (/uploadfiles) queda actualizado con 
    # acceso privado. 

    # Con este test se comprueba el correcto funcionamiento de update_files(),   
    # fetch_changes() y los hilos().
    def test_change_to_private(self):
        # Conectarse la base de datos
        connection = mysql.connector.connect(
        user='root',password='root',host='mysql',port=3306,database='db'
        )

        cursor= connection.cursor()

      
        SCOPES = ['https://www.googleapis.com/auth/drive','https://mail.google.com/']
        client = app.test_client()
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        service_drive = build('drive', 'v3', credentials=creds)
        # Nombre del archivo
        file_metadata = {'name':'archivotest2.png'}
        media = MediaFileUpload('tests/archivotest.png', mimetype='image/png')
        # Se sube el archivo al Drive y se obtiene su Id para compararlo con el que se 
        # almacena en la base de datos
        file = service_drive.files().create(body=file_metadata, media_body=media, fields='id').execute()
        file_uploaded_file = file.get("id")
        new_permission = {  'type': 'anyone', 'role': 'reader' }
        service_drive.permissions().create( fileId=file_uploaded_file, body=new_permission).execute()

        # Se simula la vista del usuario a la ruta /updatefilfes
        requests.get('http://localhost:5000/updatefiles')
        cursor.execute('Select * FROM Drivefile')
        driveFiles = cursor.fetchall()
        
        # Se obtiene los archivos de la base de datos
        
     
     

        flag_db = False
        # Se busca entre los archivos de la base de datos uno que tenga el mismo Id al del archivo que se acabo de subir.
        for filedrive in driveFiles:
            if filedrive[1] == file_uploaded_file:
                # Si se encuentra se debe validar que el acceso es publico
                if filedrive[5] == 'Public':
                    flag_db = True
        
        # Primero se valida que el archivo queda con acceso publico en la base de datos.
        assert flag_db == True
        
        # Se simula la vista del usuario a la ruta /updatefilfes para actualizar la base de datos
        requests.get('http://localhost:5000/updatefiles')
      
        
    
        flag_db_permission = False
        cursor.execute('Select * FROM Drivefile')
        driveFiles = cursor.fetchall()
       
        # Se busca entre los archivos de la base de datos uno que tenga el mismo Id al del archivo que se acabo de subir.
        for filedrive in driveFiles:
            if filedrive[1] == file_uploaded_file:
                # Si se encuentra se debe validar que el acceso es privado
                if filedrive[5] == 'Private':
                    flag_db_permission = True
        
        assert flag_db_permission == True
        
        



        
