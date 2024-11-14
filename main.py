# main.py
from graphql_client import GraphQLClient
from queries.admin_queries import get_admins_query
from queries.event_queries import get_events_query, get_events_feed_query
from config import ACCOUNT_ID, API_KEY, API_ENDPOINT
from utils import print_pretty_json

def main():
    client = GraphQLClient(API_ENDPOINT, API_KEY)

    limit = 10

    account_ids=[ACCOUNT_ID]
    filters = [
        {
        "fieldName": "pop_name",
        "operator": "is",
        "values": ["Beijing_DC2"]
        }
    ]

    query, variables = get_events_feed_query(account_ids, filters)

    try:
        response = client.execute_query(query, variables)
        print("Connection successful!")
        print_pretty_json(response)
    except Exception as e:
        print(f"Fehler: {e}")

if __name__ == "__main__":
    main()
