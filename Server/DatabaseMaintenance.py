import sqlite3
import time
import datetime
import Response
from Crypto.Cipher import AES
import hashlib
import crypto
import uuid
import os


class client_database:
    
        def __init__(self):
            con = sqlite3.connect("server.db")
            self.con =  con
            cur = con.cursor()
            self.cur = cur
            cur.execute("CREATE TABLE IF NOT EXISTS Clients(ID TEXT, Name TEXT, PublicKey TEXT, Last_Seen TEXT, AES_Key TEXT)")
            cur.execute("CREATE TABLE IF NOT EXISTS  Files(ID TEXT, File_Name TEXT, Path_Name TEXT, Verified REAL)")
            
        def get_time(self):
            unix = time.time()
            date = str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
            return date
        
        def add_register_client(self,payload, uu):
            last_seen = self.get_time()
            name = payload[0:255].decode('utf-8')
            print("name is:" ,name)
            public_key = "NULL"
            print(uu)
            str_uu = str(uu)
            aes_key = 'NULL'
            self.cur.execute("INSERT INTO Clients (ID, Name, PublicKey,  Last_Seen, AES_Key) VALUES (?, ?, ?, ?, ?)",
                             (str_uu, name, public_key, last_seen, aes_key))
            self.con.commit()
            self.con.close()
            return aes_key
        
        def get_uuid_from_name(self,payload ):
            #get uuid from register database entry
            name = payload[0:255].decode('utf-8')
            str_uu = self.cur.execute("SELECT ID FROM Clients WHERE Name=?  ORDER BY ROWID DESC",(name,))
            str_uu = self.cur.fetchone()[-1]
            nice_uu = str_uu.replace("-","")
            uu = uuid.UUID(nice_uu)
            return uu
         
        def update_db_with_keys(self, uu, public_key, aes_key):
           self.cur.execute("UPDATE Clients SET  PublicKey= ?,AES_Key = ? WHERE ID=?",(public_key, aes_key, uu))
           self.con.commit()
           self.con.close()
           
        def add_file(self,payload, verified,dir_path):
            uu = payload[0:16]
            file_name = payload[16:271].decode('utf-8')
            print("file is:" ,file_name)
            print(uu)
            str_uu = str(uu)
            file_path = os.path.join(dir_path, file_name)
            changed_file_path = file_path.rstrip(' \t\r\n\0')
            self.cur.execute("INSERT INTO Files (ID, File_Name,  Path_Name, Verified) VALUES (?, ?, ?, ?)",
                             (str_uu, file_name, changed_file_path, verified))
            self.con.commit()
            self.con.close()
            
            

 