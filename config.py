DATABASE_CONFIG = {
    'DRIVER': '{ODBC Driver 17 for SQL Server}',
    'SERVER': 'localhost',
    'DATABASE': 'CineDB',
    'TRUSTED_CONNECTION': 'yes'  # Esto permite la autenticación de Windows
}

SQLALCHEMY_DATABASE_URI = f"mssql+pyodbc://{DATABASE_CONFIG['SERVER']}/{DATABASE_CONFIG['DATABASE']}?driver={DATABASE_CONFIG['DRIVER']}&trusted_connection={DATABASE_CONFIG['TRUSTED_CONNECTION']}"
