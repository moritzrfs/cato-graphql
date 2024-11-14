ADMIN_QUERY = """
query admins($accountId: ID!, $limit: Int) {
  admins(accountID: $accountId, limit: $limit) {
    items {
      id
      email
      managedRoles {
        role {
          name
        }
      }
    }
    total
  }
}
"""

def get_admins_query(account_id: str, limit: int):
    """
    Generates a query to fetch the admins for a specific account.
    :param account_id: The account ID as a string.
    :param limit: The maximum number of admins.
    :return: The query and variables for the request.
    """
    variables = {
        "accountId": account_id,
        "limit": limit
    }
    return ADMIN_QUERY, variables
