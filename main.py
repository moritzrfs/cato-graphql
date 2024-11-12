# main.py
from graphql_client import GraphQLClient
from queries.admin_queries import get_admins_query
from config import ACCOUNT_ID, API_KEY, API_ENDPOINT
from utils import print_pretty_json

def main():
    client = GraphQLClient(API_ENDPOINT, API_KEY)

    limit = 10

    query, variables = get_admins_query(ACCOUNT_ID, limit)

    try:
        response = client.execute_query(query, variables)
        print("Connection successful!")
        print_pretty_json(response)
    except Exception as e:
        print(f"Fehler: {e}")

if __name__ == "__main__":
    main()
