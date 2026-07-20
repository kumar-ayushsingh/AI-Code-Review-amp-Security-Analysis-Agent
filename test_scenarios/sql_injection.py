def get_user_data(user_id):
    # This is a raw SQL string concatenation vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
