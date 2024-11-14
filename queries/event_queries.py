EVENT_QUERY = """
query events($accountID: ID!, $timeFrame: TimeFrame!, $measures: [EventsMeasure]) {
  events(accountID: $accountID, timeFrame: $timeFrame, measures: $measures) {
    records {
      flatFields
      fieldsMap
    }
  }
}
"""

def get_events_query(account_id: str, time_frame: str, measures: list):
    """
    Generates a query to fetch events for a specific account and time frame.
    :param account_id: The account ID as a string.
    :param time_frame: The time frame for the events (e.g., 'last_30_days').
    :param measures: The measures to aggregate (e.g., [{'fieldName': 'event_count', 'aggType': 'sum'}]).
    :return: The query and variables for the request.
    """
    variables = {
        "accountID": account_id,
        "timeFrame": time_frame,
        "measures": measures
    }
    return EVENT_QUERY, variables

EVENT_FEED_QUERY = """
query eventsFeed($accountIDs: [ID!]!, $filters: [EventFeedFieldFilterInput!]) {
  eventsFeed(accountIDs: $accountIDs, filters: $filters) {
    accounts {
      id
      errorString
      records {
        fieldsMap
      }
    }
  }
}
"""

def get_events_feed_query(account_ids: list, filters: list):
    """
    Generates a query to fetch events feed with specific filters.
    :param account_ids: The list of account IDs (e.g., ['123']).
    :param filters: List of filter conditions (e.g., [{'fieldName': 'event_type', 'operator': 'is_not', 'values': ['Sockets Management']}]).
    :return: The query and variables for the request.
    """
    variables = {
        "accountIDs": account_ids,
        "filters": filters
    }
    return EVENT_FEED_QUERY, variables