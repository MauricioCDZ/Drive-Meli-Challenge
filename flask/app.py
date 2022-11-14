import os
import pathlib
import threading

import requests
from flask import Flask, session, abort, redirect, request,render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from pip._vendor import cachecontrol
from email.message import EmailMessage
import base64
from googleapiclient.errors import HttpError
import google.auth.transport.requests
import mysql.connector
import json

app = Flask("Google Login App")
app.secret_key = "NotImportantForThisCodeChallenge"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Se cargan las credenciales desde archivos json para asegurar las claves y no colocarlas estaticas
# directamente en el codigo.
google_secre_creds = open('google_client_creds.json')
data_secret = json.load(google_secre_creds)

GOOGLE_CLIENT_ID =  data_secret["google_creds"]

# Se cargan las credenciales desde archivos json para asegurar las claves y no colocarlas estaticas
# directamente en el codigo.

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
SCOPES = ['https://www.googleapis.com/auth/drive','https://mail.google.com/']

# Lista para guardar el token de los cambios de los archivos.
saved_start_page_token = []
# Listas que usan los hilos para enviar los correos pendientes y remover el permiso publico del archivo.
pending_emails = []
pending_remove_permissions = []

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid",'https://www.googleapis.com/auth/drive','https://mail.google.com/'],
    redirect_uri="http://127.0.0.1:5000/callback"
)



# Conectar con la base de datos a traves del puerto 3306.
# Esta funcion retorna la conexion y el cursor, necesarios para ejecutar querys 
# cada vez que se necesita acceder o modificar la base de datos.
def connect_db():
    connection = mysql.connector.connect(
    user='root',password='root',host='mysql',port=3306,database='db'
    )

    cursor= connection.cursor()

    return [cursor,connection]

# Variables globales necesarias para acceder y modificar la base de datos
# Esta funcion solo se llama 1 vez en el codigo (cuando se inicia la aplicacion)
cursor,connection = connect_db()

# Decorador
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper

# Bibliografia :  https://developers.google.com/drive/api/v2/reference/permissions/delete
def remove_permission(service, file_id, permission_id):


    """Remover un permiso.

    Args:
        service: instancia de servicio de Drive API.
        file_id: id del archivo a quitar el permiso.
        permission_id: ID del permiso a remover.
    """
    service.permissions().delete(fileId=file_id, permissionId=permission_id).execute()

#Bibliografia : https://developers.google.com/gmail/api/guides/sending#python_2
def send_email(service,to,name_file):
    """Enviar corrreo.

    Args:
        service: instancia de servicio de Gmail API.
        to: correo del dueno del archivo.
        name_file: mombre del archivo.
    """
    message = EmailMessage()
    #Cuerpo del correo
    message.set_content('The access of the file: ' + name_file + ' now is private.')

    message['To'] = to

    #message['From'] = 'mauriciocd12@gmail.com'

    #Titulo del correo
    message['Subject'] = name_file + ' changed visibility.' 

    # encoded message
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    create_message = {
            'raw': encoded_message
    }

    #Accion enviar correo
    send_message = (service.users().messages().send(userId="me", body=create_message).execute())

    print(F'Message Id: {send_message["id"]}')


#Bibliografia https://developers.google.com/drive/api/quickstart/python
# Funcion necesaria para dar una lectura inicial de los archivos del drive del usuario. 
# Puesto que posteriormente a la primera lectura, lo que se va seguir verificando son
# los cambios que sufren los archivos en el drive o tambien los nuevos que se ingresan o borran.
# Esto con el fin de mejorar el rendimiento de aplicacion, puesto que solo busca nuevos cambios y 
# para no tener que iterar por todos los archivos buscando cambios (dado que Drive Api ya hace esto
# por nosotros).

def first_lecture():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
         
            return redirect("/")
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        #Se instancia un servicio para usar Drive Api
        service = build('drive', 'v3', credentials=creds)
        service_gmail = build('gmail', 'v1', credentials=creds)

  

        # Call the Drive v3 API
        # Lists or searches files.

        # Biliografia https://developers.google.com/drive/api/v3/reference/files/list
        # Se listan los primeros 1000 archivos que tenga el usuario en Drive y se escogen los campos a traer de
        # cada uno de los archivos.
        results = service.files().list(
            pageSize=1000,fields="nextPageToken, files(id, name,fileExtension,mimeType,owners,permissions,modifiedTime)").execute()
        items = results.get('files', [])

        if not items:
            print('No files found.')
            return
        print('Files:')

        files_to_insert = []

        for item in items:
            # Bandera para controlar la visibilidad de los archivos, si en algun momento de la ejecucion del ciclo
            # para determinado item esta se vuelta true, quiere decir que el archivo tiene un permiso publico 
            # o en otras palabras cualquier persona con el link puede acceder al archivo.
            was_public = False
           
            if 'permissions' in item:

                for permission in item['permissions']:
                    # Como existe un permiso con tipo anyone o cualquiera, la bandera se vuelve true y se reconoce
                    # el archivo como publico.
                    if permission['type'] == 'anyone':
                        was_public = True

                        # Se anade a la lista de los correos pendientes por enviar.
                        pending_emails.append([item['owners'][0]['emailAddress'],item['name']])
                        # Se anade a la lista para remover el permiso de publico y hacerlo solo privado.
                        pending_remove_permissions.append(item['id'])

                # Hay algunos archivos que no tiene extension asignada, a los que no poseen extension les coloco 'has no extension'
                if 'fileExtension' in item:
                    files_to_insert.append((item['id'],item['name'],item['fileExtension'],item['owners'][0]['displayName'],'Public' if was_public else 'Private' ,item['modifiedTime'],was_public))
                else:
                    files_to_insert.append((item['id'],item['name'],'has no extension',item['owners'][0]['displayName'],'Public' if was_public else 'Private',item['modifiedTime'],was_public))

            else:

        
                print(u'{0} ({1}) ({2}) ({3})'.format(item['name'], item['id'],item['mimeType'],item['owners'][0]['displayName'],item['modifiedTime']))
  
        #Upsert, si el archivo no existe entonces se inserta, de lo contrario se actualiza.
        sql = "INSERT INTO Drivefile (FileID,NameFile,Extension,OwnerName,Visibility,LastModDate,WasPublic) VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE NameFile=VALUES(NameFile), LastModDate=VALUES(LastModDate)"   
   

        print("Db connectedd")

        # Se utilizae el cursor y la conexion globales para acceder a la base de datos.
        # y se utiliza la funciona executemany para insertar todos los archivos con un solo llamado insert.
        cursor.executemany(sql, files_to_insert)
        connection.commit()

       
    except HttpError as error:
        # TODO(developer) - Handle errors from drive API.
        print(f'An error occurred: {error}')
    return 'Succesfully'



# Login para lanzar el flujo de autorizacion de permisos sobre el alcande de Drive Api y Gmail Api
@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


# Una vez se realiza el login exitosamente, se redirige a esta ruta, donde se guardan el token para acceder a 
# a las Apis.
# Bibliografia: https://github.com/code-specialist/flask_google_login/blob/main/app.py
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    #if not session["state"] == request.args["state"]:
    #    abort(500)  # State does not match!

    credentials = flow.credentials
    
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # Necesarios para cerrar sesion.
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
   

    #Se guarda el token
    with open('token.json', 'w') as token:
        token.write(credentials.to_json())

    
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # Recuperar el token de la página de inicio por primera vez, necesario para mantener el tracking de 
    # los cambios de los archivos.
    fetch_start_page_token(creds)

    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return "Hello Welcome to the MELI Challenge  <a href='/login'><button>Login</button></a>"



# Ruta para dar la bienvenida al usuario usando su nombre y tambien para realizar la primera lectura
# de los archivos. 
@app.route("/protected_area")
@login_is_required
def protected_area():
    
    first_lecture()
    threads()
  

    #return f"Hello {session['name']}! Take a look at your Drive files. <br/> <a href='/logout'><button>Logout</button></a>"
    #return f"Hello {session['name']}! Take a look at your Drive files. <br/> <a href='/readfiles'><button>Read files</button></a>"
    return redirect("/readfiles")


def thread_pending_emails():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    service_gmail = build('gmail', 'v1', credentials=creds)
    # Mientras que haya correos pendientes por enviar.
    while len(pending_emails) > 0:
        email_message = pending_emails.pop()
        send_email(service_gmail,email_message[0],email_message[1])



def thread_remove_permissions():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    service_drive = build('drive', 'v3', credentials=creds)
    # Mientras haya permisos por quitar.
    while len(pending_remove_permissions) > 0:
        file_identification = pending_remove_permissions.pop()
        remove_permission(service_drive,file_identification,'anyoneWithLink')
        


     

def threads():
    # Hilo para enviar los correos a los usuarios correspondientes
    hilo1 = threading.Thread(target=thread_pending_emails)
    # Hilo para quitar el permiso publico a los archivos.
    hilo2 = threading.Thread(target=thread_remove_permissions)
    hilo1.start()
    hilo2.start()



# Ruta para actualizar los archivos, a la funcion fetch_changes se le pasa
# el token que guarda el ultimo estado de los cambios desde la anterior lectura.
@app.route("/updatefiles")
def update_files():

    fetch_changes(saved_start_page_token[0])
    # Una vez se obtienen los cambios de los archivos y se guardan los cambios en la base de datos
    # Se proceden a eliminar los permisos publicos de los archivos y tambien a enviar los correos
    # a sus respectivos duenos, para notificarle del cambio. Eso provoca una desincronizacion entre 
    # la informacion almacenada en la base de datos y mostrada en la ruta /readfiles respecto a la informacion 
    # en el Drive del usuario. En la siguiente lectura de los datos (visitando la ruta /updatefiles) ya el
    # usuario vera los cambios surgidos por la eliminacion del permiso publico.


    # Para eliminar los permisos publicos y enviar los correos se usan hilos (Threads)
    # permitiendo que la aplicación ejecute simultáneamente varias operaciones en el mismo espacio de proceso.
    # De manera que el usuario es re-dirigido a la ruta (/readfiles) para ver los datos de la base de datos, mientras
    # que al mismo tiempo por "Detrás" se esta cambiando la visibilidad de los archivos publicos a privados y tambien
    # enviando los correos a los usuarios. 
    threads()
    return redirect("/readfiles")


# Recuperar cambios
# Para recuperar la lista de cambios para el usuario autenticado 
# actualmente, envíe una solicitud GET a la colección de cambios,
# como se detalla en la referencia de la lista.
# Bibliografia: https://developers.google.com/drive/api/guides/manage-changes#python_1
def fetch_changes(saved_start_page_token1):
    """Retrieve the list of changes for the currently authenticated user.
        prints changed file's ID
    Args:
        saved_start_page_token : StartPageToken for the current state of the
        account.
    Returns: saved start page token.

    """
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
         
            return redirect("/")
        with open('token.json', 'w') as token:
            token.write(creds.to_json())



    try:
        # create drive api client
        service = build('drive', 'v3', credentials=creds)

        # Begin with our last saved start token for this user or the
        # current token from getStartPageToken()

        # Se comienza con el ultimo token guardado para este usuario autenticado
        page_token = saved_start_page_token1
     
    
        private_files = [] # Archivos privados.
        public_files = [] # Archivo publicos(Archivos que tienen un permiso en el cualquier persona con el link puede acceder)
        deleted_files =[] #Archivos eliminados.
        while page_token is not None:
            # Se recuperan los ultimos cambios en los archivos desde el ultimo token guardado.
            response = service.changes().list(pageToken=page_token,
                                              spaces='drive').execute()
          
            
            # Ciclo por cada cambio realizado. 
            for change in response.get('changes'):
                is_public = False
                
                # Process change
                print(F'Change found for file: {change.get("fileId")}')
                # Se revisa si el archivo fue elimando o si el usuario ya no tiene permisos sobre este
                # Es True si alguna de las dos condiciones es verdadera.
                visibility_file = change.get("removed")
                
                
                if not(visibility_file):
                    # Se trae la informacion del archivo desde drive a traves de la funcion Get
                    file_changed = service.files().get(fileId=change.get("fileId"),fields="id, name,fileExtension,mimeType,owners,permissions,modifiedTime" ).execute()        
                    if 'permissions' in file_changed:

                        for permission in file_changed['permissions']:
                            # Si el archivo es publico 
                            if permission['type'] == 'anyone':
                                is_public = True
                                
                                

                                # Se anade a la lista de los correos pendientes por enviar.
                                pending_emails.append([file_changed['owners'][0]['emailAddress'],file_changed['name']])
                                # Se anade a la lista para remover el permiso de publico y hacerlo solo privado.
                                pending_remove_permissions.append(file_changed['id'])
                                
                                if 'fileExtension' in file_changed:
                                    public_files.append((file_changed['id'],file_changed['name'],file_changed['fileExtension'],file_changed['owners'][0]['displayName'],'Public',file_changed['modifiedTime'],True))
                                else:
                                    public_files.append((file_changed['id'],file_changed['name'],'has no extension',file_changed['owners'][0]['displayName'],'Public',file_changed['modifiedTime'],True))
                        if not(is_public):
                            if 'fileExtension' in file_changed:
                                private_files.append((file_changed['id'],file_changed['name'],file_changed['fileExtension'],file_changed['owners'][0]['displayName'],'Private',file_changed['modifiedTime']))
                            else:
                                private_files.append((file_changed['id'],file_changed['name'],'has no extension',file_changed['owners'][0]['displayName'],'Private',file_changed['modifiedTime']))





                else:
                    # Si ya no tiene permisos se anade a la lista archivos eliminados,
                    # para posteriormente actualizarlo en la base de datos.
                 
                    deleted_files.append(('Sin permisos',change.get("fileId")))
                 
                
            if 'newStartPageToken' in response:
                # Last page, save this token for the next polling interval.
                # Se guarda el token para la proxima lectura de cambios.
                saved_start_page_token[0] = response.get('newStartPageToken')

            if len(private_files)>0:

                sql = "INSERT INTO Drivefile (FileID,NameFile,Extension,OwnerName,Visibility,LastModDate) VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE NameFile=VALUES(NameFile), LastModDate=VALUES(LastModDate),Visibility = VALUES(Visibility)"   
                cursor.executemany(sql, private_files)
                connection.commit()

            if len(public_files)>0:
                sql = "INSERT INTO Drivefile (FileID,NameFile,Extension,OwnerName,Visibility,LastModDate,WasPublic) VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE NameFile=VALUES(NameFile), LastModDate=VALUES(LastModDate),Visibility = VALUES(Visibility) ,WasPublic = VALUES(WasPublic)"   
                cursor.executemany(sql, public_files) 
                connection.commit()

            if len(deleted_files)>0:
               
                sql = "UPDATE Drivefile SET Visibility = %s WHERE FileID = %s"
                cursor.executemany(sql, deleted_files)
                connection.commit()
                
            page_token = response.get('nextPageToken')

    except HttpError as error:
        print(F'An error occurred: {error}')
        saved_start_page_token1 = None

    return saved_start_page_token1

# Para las aplicaciones de Google Drive que necesitan realizar un seguimiento 
# de los cambios en los archivos, la colección de cambios proporciona una manera 
# eficiente de detectar cambios en todos los archivos, incluidos los que se han 
# compartido con un usuario. La colección funciona proporcionando el estado actual 
# de cada archivo, si y solo si el archivo ha cambiado desde un momento determinado.

# Recuperar el token de la página de inicio por primera vez
# Para solicitar el token de página para el estado actual de la cuenta

# Almacene y use este token en la llamada inicial a changes.list.
# Bibliografia: https://developers.google.com/drive/api/guides/manage-changes
def fetch_start_page_token(creds):
    """Retrieve page token for the current state of the account.
    Returns & prints : start page token
    """
   
    try:
        # create drive api client
        service = build('drive', 'v3', credentials=creds)

        # pylint: disable=maybe-no-member
        response = service.changes().getStartPageToken().execute()
        print(F'Start token: {response.get("startPageToken")}')

    except HttpError as error:
        print(F'An error occurred: {error}')
        response = None

    if len(saved_start_page_token) == 0:
        saved_start_page_token.append(response.get('startPageToken'))



@app.route("/readfiles")
def connect_db():

    cursor.execute('Select * FROM Drivefile')
    driveFiles = cursor.fetchall()

    return render_template('index.html', files=driveFiles)



if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=5000)
