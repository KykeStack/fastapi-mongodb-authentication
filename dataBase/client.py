from pymongo.mongo_client import MongoClient
from pymongo.database import Database
from pymongo.server_api import ServerApi
from utils.bcolors import Colors

from core.config import settings

class Client:
    def __init__(self, uri: str) -> None:
        self.uri = uri
    
    def connect_to_database(self) -> MongoClient:
        try:
            session = MongoClient(self.uri)
            print(f"{Colors.OKGREEN}INFO{Colors.ENDC}:     {Colors.HEADER}Started database connection.{Colors.ENDC}")
            return session
        except Exception as e:
            return e
        
    def ping_database(self):
        try:
            client = MongoClient(self.uri, server_api=ServerApi('1'))
            client.admin.command('ping')
            print(f"{Colors.OKGREEN}INFO{Colors.ENDC}:     {Colors.HEADER}Pinged your deployment. You successfully connected to MongoDB!{Colors.ENDC}")
        except Exception as e:
            return e

session: Database = Client(settings.MONGODB_URL).connect_to_database()[settings.DATABASE_NAME]


if __name__ == "__main__":
    ...