import sqlite3
import pickle
from scripts.shared import *
from threading import Condition

class PeerTable ():
    """
    Object for interacting with the DB
    Single table DB
    records represent known peers on the network
    record 0 represents the host
    """
    def __init__(self, file_path : str = "./db/peerTable") -> None:
        self.db_lock = Condition()
        self.lock_timeout = 10 # 10 seconds
        # Our hardcoded commands for easy reference
        self.file_path = file_path
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
        self.conn.close()
        return
    
    def _str_format(self, string : str) -> str:
        """
        when formatting SQL expression strings, need string to become either 'string' or NULL
        """
        if string != 'NULL':
            return "'"+string+"'"
        return string
    
    def check_if_identifier_exists(self, identifier : str) -> bool:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT identifier FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()
        conn.close()
        self.db_lock.release() # release the lock
        if row:
            return True
        return False
        
    ## Getters and Setters
    def get_identifier_by_last_addr(self, last_addr : str):
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT identifier, lastSeenTime FROM PeerTable WHERE lastSeenAddress = {0}""".format(self._str_format(last_addr))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        rows = cursor.fetchall()
        if not rows:
            return None
        latest = 0
        ident = None
        for peer in rows: # gets the identifier of the peer who used that address most recently
            identifier = peer[0]
            lastSeenTime = peer[1]
            if lastSeenTime > latest:
                latest = lastSeenTime
                ident = identifier
        conn.close()
        self.db_lock.release() # release the lock
        return ident

    def get_user_p_key(self, identifier : str) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT pubKey FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        conn.close()
        self.db_lock.release() # release the lock
        return row

    def update_user_s_key(self, identifier : str, new_s_key : str) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command = """UPDATE PeerTable SET symKey = {0} WHERE identifier = {1}""".format(self._str_format(new_s_key), self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        conn.commit()
        conn.close()
        self.db_lock.release() # release the lock
        return True
    
    def get_user_s_key(self, identifier : str) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT symKey FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        conn.close()
        self.db_lock.release() # release the lock
        return row

    def update_user_last_address(self, identifier : str, last_address : str) -> bool:
        self.db_lock.acquire() # try to acquire the db lock
        command = """UPDATE PeerTable SET lastSeenAddress={0} WHERE identifier = {1}""".format(self._str_format(last_address), self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        conn.commit()
        conn.close()
        self.db_lock.release() # release the lock
        return True
    
    def get_user_last_address(self, identifier : str) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT lastSeenAddress FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        conn.close()
        self.db_lock.release() # release the lock
        return row
    
    def update_user_last_time(self, identifier : str, last_time : float) -> bool:
        self.db_lock.acquire() # try to acquire the db lock
        command = """UPDATE PeerTable SET lastSeenTime={0} WHERE identifier = {1}""".format(last_time, self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        conn.commit()
        conn.close()
        self.db_lock.release() # release the lock
        return True
    
    def get_user_last_time(self, identifier : str) -> float:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT lastSeenTime FROM PeerTable WHERE identifier = {0}""".format(self._str_format(identifier))
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()[0]
        conn.close()
        self.db_lock.release() # release the lock
        return row
    
    def get_host_identifier(self) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT identifier FROM PeerTable WHERE id=1"""
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()
        conn.close()
        self.db_lock.release() # release the lock
        if row:
            return row[0]
        return row
    
    def get_host_key(self) -> str:
        self.db_lock.acquire() # try to acquire the db lock
        command  = """SELECT pubKey FROM PeerTable WHERE id=1"""
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        row = cursor.fetchone()
        conn.close()
        self.db_lock.release() # release the lock
        if row:
            return row[0] # retrieve key from returned tuple
        return row # return None
    
    def get_peers(self):
        self.db_lock.acquire() # try to acquire the db lock
        command = """SELECT identifier, pubKey, lastSeenAddress, lastSeenTime FROM PeerTable"""
        conn = sqlite3.connect(self.file_path)
        cursor = conn.cursor() # create cursor
        cursor.execute(command)
        rows = cursor.fetchall()
        conn.close()
        self.db_lock.release() # release the lock
        return rows[1:] # remove the first peer (the host)
    
    def update_peers(self, rows : list) -> bool:
        self.db_lock.acquire() # try to acquire the db lock
        conn = sqlite3.connect(self.file_path)
        for peer in rows:
            identifier = peer[0]
            pubKey = peer[1]
            lastSeenAddress = peer[2]
            lastSeenTime = peer[3]
            command1 = """UPDATE PeerTable
                            SET lastSeenAddress={0}, lastSeenTime={1}
                            WHERE identifier={2}""".format(self._str_format(lastSeenAddress),
                                                           lastSeenTime,
                                                           self._str_format(identifier))
            command2 = """INSERT OR IGNORE INTO PeerTable (identifier, pubKey, lastSeenAddress, lastSeenTime) VALUES ({0}, {1}, {2}, {3})""".format(self._str_format(identifier),
                                                                                                                                                    self._str_format(pubKey),
                                                                                                                                                    self._str_format(lastSeenAddress),
                                                                                                                                                    lastSeenTime)
            conn.execute(command1)
            conn.execute(command2)
        conn.commit()
        conn.close()
        self.db_lock.release() # release the lock
        return True
    
    def get_serialised_peers(self):
        rows = self.get_peers()
        serialised_rows = pickle.dumps(rows, 5) # serialise the returned rows
        return serialised_rows
    
    def update_serialised_peers(self, serialised_rows : bytes) -> bool:
        rows = pickle.loads(serialised_rows)
        return self.update_peers(rows)
    
    def new_host(self, ident : str,
                p_key : str,
                last_address : str,
                last_time : float,
                id : int = 1) -> bool:
        """
        Adds a new host to the database
        """
        self.db_lock.acquire() # try to acquire the db lock
        command = """INSERT INTO PeerTable(id, identifier, pubKey, lastSeenAddress, lastSeenTime) VALUES({0}, {1}, {2}, {3}, {4});""".format(id,
                                                                                                                            self._str_format(ident),    
                                                                                                                            self._str_format(p_key),
                                                                                                                            self._str_format(last_address),
                                                                                                                            last_time)
        try:
            conn = sqlite3.connect(self.file_path)
            cursor = conn.cursor() # create cursor
            cursor.execute(command)
            conn.commit()
            conn.close()
            self.db_lock.release() # release the lock
            t_print("Added new host to db")
        except sqlite3.IntegrityError:
            t_print("host already exists.")
            conn.close()
            self.db_lock.release() # release the lock
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
        self.db_lock.acquire() # try to acquire the db lock
        command = """INSERT INTO PeerTable(pubKey, identifier, symKey, lastSeenAddress, lastSeenTime) VALUES({0}, {1}, {2}, {3}, {4});""".format(self._str_format(p_key),
                                                                                                                                        self._str_format(identifier),
                                                                                                                                        self._str_format(s_key),
                                                                                                                                        self._str_format(last_address),
                                                                                                                                        last_time)
        try:
            conn = sqlite3.connect(self.file_path)
            cursor = conn.cursor() # create cursor
            cursor.execute(command)
            conn.commit()
            conn.close()
            self.db_lock.release() # release the lock
            t_print("Added new user to db")
        except sqlite3.IntegrityError:
            t_print("user with public key specified already exists.")
            conn.close()
            self.db_lock.release() # release the lock
            return True
        return False
    