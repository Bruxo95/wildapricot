import datetime
import urllib.request
import urllib.error
import urllib.parse
import json
import base64
import pandas as pd
from tabulate import tabulate  # Importar a biblioteca tabulate


class WaApiClient(object):
    """Wild apricot API client."""
    auth_endpoint = "https://oauth.wildapricot.org/auth/token"
    api_endpoint = "https://api.wildapricot.org"
    _token = None
    client_id = None
    client_secret = None

    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate_with_apikey(self, api_key, scope=None):
        """Perform authentication by API key and store result for execute_request method.

        Args:
            api_key (str): Secret API key from account settings.
            scope (str, optional): Scope of authentication request. If None, full list of API scopes will be used.
        """
        scope = "auto" if scope is None else scope
        data = {
            "grant_type": "client_credentials",
            "scope": scope
        }
        encoded_data = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.auth_endpoint, encoded_data, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        auth_header = base64.b64encode(('APIKEY:' + api_key).encode()).decode()
        request.add_header("Authorization", 'Basic ' + auth_header)
        response = urllib.request.urlopen(request)
        self._token = self._parse_response(response)
        self._token.retrieved_at = datetime.datetime.now()

    def execute_request(self, api_url, api_request_object=None, method=None):
        """Perform API request and return result as an instance of ApiObject or list of ApiObjects.

        Args:
            api_url (str): Absolute or relative API resource URL.
            api_request_object (dict, optional): Any JSON serializable object to send to API.
            method (str, optional): HTTP method of API request. Default: GET if api_request_object is None else POST.

        Returns:
            ApiObject or list: Parsed response from the API.
        """
        if self._token is None:
            raise ApiException("Access token is not obtained. "
                              "Call authenticate_with_apikey or authenticate_with_contact_credentials first.")

        if not api_url.startswith("http"):
            api_url = self.api_endpoint + api_url

        if method is None:
            method = "GET" if api_request_object is None else "POST"

        request = urllib.request.Request(api_url, method=method)
        if api_request_object is not None:
            request.data = json.dumps(api_request_object, cls=_ApiObjectEncoder).encode()

        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.add_header("Authorization", "Bearer " + self._get_access_token())

        try:
            response = urllib.request.urlopen(request)
            return self._parse_response(response)
        except urllib.error.HTTPError as httpErr:
            if httpErr.code == 400:
                raise ApiException(httpErr.read().decode())
            else:
                raise

    def _get_access_token(self):
        """Get the access token, refreshing it if necessary."""
        expires_at = self._token.retrieved_at + datetime.timedelta(seconds=self._token.expires_in - 100)
        if datetime.datetime.utcnow() > expires_at:
            self._refresh_auth_token()
        return self._token.access_token

    def _refresh_auth_token(self):
        """Refresh the authentication token."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._token.refresh_token
        }
        encoded_data = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.auth_endpoint, encoded_data, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        auth_header = base64.b64encode((self.client_id + ':' + self.client_secret).encode()).decode()
        request.add_header("Authorization", 'Basic ' + auth_header)
        response = urllib.request.urlopen(request)
        self._token = self._parse_response(response)
        self._token.retrieved_at = datetime.datetime.now()

    @staticmethod
    def _parse_response(http_response):
        """Parse the HTTP response and return an ApiObject or list of ApiObjects."""
        decoded = json.loads(http_response.read().decode())
        if isinstance(decoded, list):
            return [ApiObject(item) for item in decoded]
        elif isinstance(decoded, dict):
            return ApiObject(decoded)
        else:
            return decoded


class ApiException(Exception):
    """Custom exception for API errors."""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ApiObject(object):
    """Represent any API call input or output object."""
    def __init__(self, state):
        self.__dict__ = state
        for key, value in vars(self).items():
            if isinstance(value, dict):
                self.__dict__[key] = ApiObject(value)
            elif isinstance(value, list):
                self.__dict__[key] = [ApiObject(item) if isinstance(item, dict) else item for item in value]

    def __str__(self):
        return json.dumps(self.__dict__, indent=2)

    def __repr__(self):
        return json.dumps(self.__dict__, indent=2)


class _ApiObjectEncoder(json.JSONEncoder):
    """Custom JSON encoder for ApiObject."""
    def default(self, obj):
        if isinstance(obj, ApiObject):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)


# Função para converter ApiObject em dicionário
def api_object_to_dict(api_object):
    """Converte um ApiObject em um dicionário."""
    if isinstance(api_object, ApiObject):
        return api_object.__dict__
    elif isinstance(api_object, list):
        return [api_object_to_dict(item) for item in api_object]
    else:
        return api_object


# Exemplo de uso
if __name__ == "__main__":
    # Substitua pelos seus próprios valores
    API_KEY = "YOU KEY"  # Sua API Key do WildApricot

    # Crie uma instância do cliente
    api = WaApiClient(client_id=None, client_secret=None)  # Não é necessário client_id e client_secret para API Key

    # Autentique com a API Key
    api.authenticate_with_apikey(api_key=API_KEY)

    # Passo 1: Obter o Account ID
    accounts = api.execute_request("/v2/accounts")
    if len(accounts) > 0:
        ACCOUNT_ID = accounts[0].Id
        print(f"Account ID obtido com sucesso: {ACCOUNT_ID}")
    else:
        print("Nenhuma conta encontrada.")
        exit()

    # Passo 2: Listar contatos
    contacts = api.execute_request(f"/v2/Accounts/{ACCOUNT_ID}/Contacts")

    # Verificar se a resposta é um único objeto ou uma lista de contatos
    if isinstance(contacts, ApiObject):
        # Se for um único objeto, verifique se ele contém uma lista de contatos
        if hasattr(contacts, "Contacts"):
            contacts_list = contacts.Contacts
        else:
            contacts_list = [contacts]  # Trata como uma lista com um único contato
    elif isinstance(contacts, list):
        contacts_list = contacts
    else:
        print("Formato de resposta inesperado.")
        exit()

    # Converter os contatos em uma lista de dicionários
    contacts_list = [api_object_to_dict(contact) for contact in contacts_list]

    # Criar um DataFrame com os dados dos contatos
    df = pd.json_normalize(contacts_list)

    # Exibir a tabela no prompt usando tabulate
    print("\nTabela de Contatos:")
    print(tabulate(df, headers="keys", tablefmt="pretty", showindex=False))