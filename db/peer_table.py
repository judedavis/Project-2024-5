import sqlite3
from scripts.shared import *

class PeerTable ():
    """
    Object for interacting with the DB
    Single table DB
    records represent known peers on the network
    record 0 represents the host
    """
    def __init__(self, file_path : str = "./db/peerTable") -> None:
        # Our hardcoded commands for easy reference
        self.commands = {
            "create_table": """CREATE TABLE IF NOT EXISTS PeerTable (id INTEGER PRIMARY KEY AUTOINCREMENT, identifier TEXT UNIQUE, pubKey TEXT UNIQUE, symKey TEXT, lastSeenAddress TEXT, lastSeenTime FLOAT);""",
        }
        # connect to the peertable database
        try:
            self.conn = sqlite3.connect(file_path)
        except sqlite3.OperationalError:
            t_print("PeerTable: Failed to open DB")
        cursor = self.conn.cursor()

        # create peertable table if doesn't exist
        cursor.execute(self.commands["create_table"])
        self.conn.commit()
        return
    
    def _str_format(self, string : str) -> str:
        """
        when formatting SQL expression strings, need string to become either 'string' or NULL
        """
        if string != 'NULL':
            return "'"+string+"'"
        return string
    
    def check_if_identifier_exists(self, identifier : str) -> bool:
        command = """SELECT identifier FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        row = self.cursor.fetchone()
        
        if row:
            return True
        return False
        
    ## Getters and Setters
    def update_user_s_key(self, identifier : str, new_s_key : str) -> bool:
        command = """UPDATE PeerTable SET symKey = {0} WHERE identifier = {1}""".format(self._str_format(new_s_key), self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_s_key(self, identifier : str) -> str:
        command = """SELECT symKey FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        return row

    def update_user_last_address(self, identifier : str, last_address : str) -> bool:
        command = """UPDATE PeerTable SET lastSeenAddress={0} WHERE identifier = {1}""".format(self._str_format(last_address), self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_last_address(self, identifier : str) -> str:
        command = """SELECT lastSeenAddress FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        return row
    
    def update_user_last_time(self, identifier : str, last_time : float) -> bool:
        command = """UPDATE PeerTable SET lastSeenTime={0} WHERE identifier = {1}""".format(last_time, self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_last_time(self, identifier : str) -> float:
        command = """SELECT lastSeenTime FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        return row
    
    def get_host_key(self) -> str:
        command  = """SELECT pubKey FROM PeerTable WHERE id=1"""
        cursor = self.conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()
        if row:
            return row[0] # retrieve key from returned tuple
        return row # return None
    
    def new_host(self, p_key : str,
                last_address : str,
                last_time : float,
                id : int = 1) -> bool:
        """
        Adds a new host to the database
        """
        command = """INSERT INTO PeerTable(id, identifier, pubKey, lastSeenAddress, lastSeenTime) VALUES({0}, 'host', {1}, {2}, {3});""".format(id,
                                                                                                                            self._str_format(p_key),
                                                                                                                            self._str_format(last_address),
                                                                                                                            last_time)
        try:
            cursor = self.conn.cursor() # create cursor
            cursor.execute(command)
            self.conn.commit()
            t_print("Added new user to db")
        except sqlite3.IntegrityError:
            t_print("host already exists.")
            return False
        return True

    def new_user(self, p_key : str,
                 identifier : str,
                 last_address : str,
                 last_time : float,
                 s_key : str = 'NULL',) -> bool:
        """
        Adds a new user to the database
        """
        command = """INSERT INTO PeerTable(pubKey, identifier, symKey, lastSeenAddress, lastSeenTime) VALUES({0}, {1}, {2}, {3}, {4});""".format(self._str_format(p_key),
                                                                                                                                        self._str_format(identifier),
                                                                                                                                        self._str_format(s_key),
                                                                                                                                        self._str_format(last_address),
                                                                                                                                        last_time)
        try:
            cursor = self.conn.cursor() # create cursor
            cursor.execute(command)
            self.conn.commit()
            t_print("Added new user to db")
        except sqlite3.IntegrityError:
            t_print("user with public key specified already exists.")
            return True
        return False
    
    def exit(self) -> None:
        t_print("Closing database connection.")
        self.conn.close()
        return
        