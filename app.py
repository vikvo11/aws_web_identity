from flask import Flask, redirect, request, url_for
from flask import session
from authlib.integrations.flask_client import OAuth

from jose import jwt
from boto3 import client as boto3_client
import os
import requests
import base64
import json
import urllib

from authlib.jose.errors import BadSignatureError, ExpiredTokenError

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Используем Authlib для интеграции с OAuth 2.0
oauth = OAuth(app)

# Настраиваем Google OAuth 2.0
google = oauth.register(
    name='google',
    client_id='#client_id',
    client_secret='#client_secret',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    #client_kwargs={'scope': 'email profile'},
    client_kwargs={'scope': 'email profile', 'prompt': 'select_account'},
    redirect_uri='http://127.0.0.1:5555/authorize/google'
)

# Настраиваем Facebook OAuth 2.0
facebook = oauth.register(
    name='facebook',
    client_id='YOUR_FACEBOOK_CLIENT_ID',
    client_secret='YOUR_FACEBOOK_CLIENT_SECRET',
    access_token_url='https://graph.facebook.com/v6.0/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/v6.0/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    userinfo_endpoint='https://graph.facebook.com/me',
    client_kwargs={'scope': 'email'},
)

# # AWS STS клиент
sts_client = boto3_client(
    'sts',
    aws_access_key_id='#aws_access_key_id',
    aws_secret_access_key='#aws_secret_access_key',
    region_name='us-west-2'  # Измените на ваш AWS регион
    )

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, 'your_secret_key', algorithms=['HS256'])
        return decoded
    except:
        return None

def get_federation_url(sts_response):
    # Закодировать учетные данные STS в JSON
    session_json = json.dumps({
        "sessionId": sts_response["Credentials"]["AccessKeyId"],
        "sessionKey": sts_response["Credentials"]["SecretAccessKey"],
        "sessionToken": sts_response["Credentials"]["SessionToken"]
    })

    # Бинарно закодировать учетные данные STS
    binary_session_json = session_json.encode('utf-8')

    # Получить бинарное представление учетных данных в base64
    base64_session_json = base64.b64encode(binary_session_json).decode('utf-8')

    # Создать URL для входа в консоль AWS с временными учетными данными
    federation_url = (
        f"https://signin.aws.amazon.com/federation?Action=login&Issuer=example.com&Destination="
        f"https%3A%2F%2Fconsole.aws.amazon.com%2F&SigninToken={base64_session_json}"
    )

    return federation_url


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login/google')

@app.route('/home')
def hello_world():
    return 'Hello, World!'

@app.route('/')
def homepage():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/<provider>')
def login(provider):
    if provider == 'google':
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    elif provider == 'facebook':
        redirect_uri = url_for('authorize_facebook', _external=True)
        return facebook.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    id_token = token.get('id_token')  # Это JWT, который содержит информацию о пользователе

    print(id_token)

    
    # decoded_token = decode_jwt(id_token)
    # print(decoded_token)

    # Get client id from google console
    client_id = '#client_id'

    # get public key from jwks uri
    response = requests.get("https://www.googleapis.com/oauth2/v3/certs")

    # gives the set of jwks keys.the keys has to be passed as it is to jwt.decode() for signature verification.
    key = response.json()

    # get the algorithm type from the request header
    access_token = token.get('access_token')
    

    algorithm = jwt.get_unverified_header(id_token).get('alg') # RS256
    user_info = jwt.decode(token=id_token, key=key, algorithms=algorithm, audience=client_id, access_token=access_token)

    #user_info = jwt.decode(token=id_token, key=key, algorithms=algorithm,audience=client_id)

    print(user_info)

    # sts_client = boto3_client(
    # 'sts',
    # aws_access_key_id='#aws_access_key_id',
    # aws_secret_access_key='#aws_secret_access_key',
    # region_name='us-west-2'  # Измените на ваш AWS регион
    # )


    response = sts_client.assume_role_with_web_identity(
    RoleArn="arn:aws:iam::account_id:role/role_name",  # Измените на ARN вашей роли
    RoleSessionName="GoogleFederatedLogin",
    WebIdentityToken=id_token,  # Google ID токен
    )

    print(f'response= {response}')
    # Теперь у вас есть временные учетные данные, которые вы можете использовать для доступа к AWS-ресурсам

    # Получаем учетные данные безопасности из ответа
    credentials = response['Credentials']

    # Подготавливаем сессию
    session = {
        "sessionId": credentials['AccessKeyId'],
        "sessionKey": credentials['SecretAccessKey'],
        "sessionToken": credentials['SessionToken']
    }

    # Кодируем сессию в URL
    session_json = json.dumps(session)
    session_url = urllib.parse.quote(session_json)

    # Создаем токен входа
    request_parameters = "?Action=getSigninToken&Session=" + session_url
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters

    response = requests.get(request_url)
    response_json = response.json()  # Получение JSON из ответа
    signin_token = response_json.get('SigninToken')  # Извлечение SigninToken из JSON
    print(f'signin_token={signin_token}')

    #signin_token = "ваш_signin_token_здесь"
    signin_url = f"https://signin.aws.amazon.com/federation?Action=login&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F&SigninToken={signin_token}"


    print(f'URL={signin_url}')


    #return redirect('/home')
    return redirect(signin_url)

@app.route('/authorize/facebook')
def authorize_facebook():
    token = facebook.authorize_access_token()
    # Примечание: Facebook не предоставляет ID токен, как Google. Вместо этого, вы должны будете использовать access_token
    access_token = token.get('access_token')

    # Здесь вы можете добавить свою логику для выбора IAM-роли, основанной на информации о пользователе

    response = sts_client.assume_role_with_web_identity(
        RoleArn="arn:aws:iam::account-id:role/facebook-federated-role",  # Измените на ARN вашей роли
        RoleSessionName="FacebookFederatedLogin",
        WebIdentityToken=access_token,  # Facebook access token
        ProviderId="graph.facebook.com"
    )
    # Теперь у вас есть временные учетные данные, которые вы можете использовать для доступа к AWS-ресурсам

    

    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=True)
