# graphql_client.py
import requests

class GraphQLClient:
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def execute_query(self, query: str, variables: dict = None):
        """
        Executes a GraphQL query and returns the response.
        :param query: The GraphQL query as a string.
        :param variables: Optional: The variables for the query as a dictionary.
        :return: The API response as JSON.
        """
        data = {
            "query": query,
            "variables": variables or {}
        }

        response = requests.post(self.api_url, headers=self.headers, json=data)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Error with request: {response.status_code} - {response.text}")
