import sqlite3
from scripts.shared import *

class PeerTable ():
    def __init__(self, file_path : str = "./db/peerTable") -> None:
        # Our hardcoded commands for easy reference
        self.commands = {
            "create_table": """CREATE TABLE IF NOT EXISTS PeerTable (id INTEGER PRIMARY KEY AUTOINCREMENT, pubKey TEXT UNIQUE, symKey TEXT, lastSeenAddress TEXT, lastSeenTime FLOAT);""",
        }
        # connect to the peertable database
        try:
            self.conn = sqlite3.connect(file_path)
        except sqlite3.OperationalError:
            t_print("PeerTable: Failed to open DB")
        self.cursor = self.conn.cursor()

        # create peertable table if doesn't exist
        self.cursor.execute(self.commands["create_table"])
        self.conn.commit()
        return
    
    def _str_format(self, string : str) -> str:
        """
        when formatting SQL expression strings, need string to become either 'string' or NULL
        """
        if string != 'NULL':
            return "'"+string+"'"
        return string
    
    ## Getters and Setters
    def update_user_s_key(self, p_key : str, new_s_key : str) -> bool:
        command = """UPDATE PeerTable SET symKey = {0} WHERE pubKey = {1}""".format(self._str_format(new_s_key), self._str_format(p_key))
        self.cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_s_key(self, p_key : str) -> str:
        command = """SELECT symKey FROM PeerTable WHERE pubKey = {0}""".format(self._str_format(p_key))
        self.cursor.execute(command)
        row = self.cursor.fetchone()[0]
        self.cursor = self.conn.cursor() # reset cursor
        return row

    def update_user_last_address(self, p_key : str, last_address : str) -> bool:
        command = """UPDATE PeerTable SET lastSeenAddress={0} WHERE pubKey = {1}""".format(self._str_format(last_address), self._str_format(p_key))
        self.cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_last_address(self, p_key : str) -> str:
        command = """SELECT lastSeenAddress FROM PeerTable WHERE pubKey = {0}""".format(self._str_format(p_key))
        self.cursor.execute(command)
        row = self.cursor.fetchone()[0]
        self.cursor = self.conn.cursor() # reset cursor
        return row
    
    def update_user_last_time(self, p_key : str, last_time : float) -> bool:
        command = """UPDATE PeerTable SET lastSeenTime={0} WHERE pubKey = {1}""".format(last_time, self._str_format(p_key))
        self.cursor.execute(command)
        self.conn.commit()
        return True
    
    def get_user_last_time(self, p_key : str) -> str:
        command = """SELECT lastSeenTime FROM PeerTable WHERE pubKey = {0}""".format(self._str_format(p_key))
        self.cursor.execute(command)
        row = self.cursor.fetchone()[0]
        self.cursor = self.conn.cursor() # reset cursor
        return row
    

    def new_user(self, p_key : str,
                last_address : str,
                last_time : float,
                s_key : str = 'NULL',) -> bool:
        """
        Adds a new user to the database
        """
        command = """INSERT INTO PeerTable(pubKey, symKey, lastSeenAddress, lastSeenTime) VALUES({0}, {1}, {2}, {3});""".format(self._str_format(p_key),
                                                                                                                                      self._str_format(s_key),
                                                                                                                                      self._str_format(last_address),
                                                                                                                                      last_time)
        try:
            self.cursor.execute(command)
            self.conn.commit()
            t_print("Added new user to db")
        except sqlite3.IntegrityError:
            t_print("user with public key specified already exists.")
        return
    
    def exit(self) -> None:
        t_print("Closing database connection.")
        self.conn.close()
        return
        