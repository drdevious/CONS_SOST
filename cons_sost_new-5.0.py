#! /bin/env python

#######################################################################
### DGF 7/7/2014                                                    ###
#######################################################################

#########################
### IMPORT DEI MODULI ###
#########################

import os, random, struct, sys, shutil
from stat import ST_SIZE
import re, csv
import fnmatch
import hashlib, base64
import subprocess
import urllib, urllib2
import time
import datetime
from datetime import date, timedelta, datetime
import logging
import ConfigParser
import xml.etree.ElementTree as ET
import xml.dom.ext
import xml.dom.minidom
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import psycopg2
import httplib

#########################################
### DICHIARAZIONE COSTANTI SIMBOLICHE ###
#########################################

PATH_HOME = "/opt/CONS_SOST_NEW/"
PATH_LOG = PATH_HOME+"Log/"
PATH_CONFIG = PATH_HOME+"Config/"
PATH_WORK = PATH_HOME+"Work/"
PATH_RQST = PATH_HOME+"FileRQST/"
PATH_INTEGRITY_VIOLATION = PATH_HOME+"FILE_VIOLATION/"
CONFIG_FILE = PATH_CONFIG+"config.cfg"
PATH_CERTIFICATE = PATH_HOME+"CERTIFICATE/"
CA_CERT = "xxx.pem" # certificato
PATH_INDEX_MONTHLY = "/xxx/DOWNLOAD/FileIndex/"

### Comandi unix ###
OPENSSL = "/usr/bin/openssl"
GZIP = "/usr/bin/gzip"
CAT = "/usr/bin/cat"
CURL = "/usr/bin/curl"
TAR = "/usr/sbin/tar"

### primo giorno del mese per fare le statistiche mensili ###
FIRST_DAY_OF_MONTH='01'

### numero di giorni indietro rispetto ai file che devo trattare ###
TIME_DELTA = 1

### Db parameter ###
CONNECT_STRING = "host=localhost dbname=cons_sost user=consost password=c0ns0st123"

### Timestamp Parameter ###
#TS_URL = "https://XX.XX.XX.XX/TSA/GetTimeStamp.ashx"
TS_URL = "https://XX.XX.XX.XX/TSA/GetTimeStamp.ashx"
TS_PWD = "user@x23"
TS_USER = "mt_user"
TS_POLICY = "X.X.XX.XX.X.XX.x"

### Trap per nagios ###
NSCA_PATH = "/usr/local/nagios/"
IP_NAGIOS = "nagios IP"

### definizione oggetto logger ###
SYSTEM_DATE=time.strftime("%Y%m%d")
LOG_FILENAME = PATH_LOG+"/cons_sost_new-"+SYSTEM_DATE+".log"
logger = logging.getLogger("consost_new-5.0.py")
hdlr = logging.FileHandler(LOG_FILENAME)
FORMAT = logging.Formatter('%(asctime)s - [%(levelname)s] %(message)s')
hdlr.setFormatter(FORMAT)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

### definizione dell'oggetto parser per la lettura del file di configurazione ###
parser = ConfigParser.ConfigParser()
parser.read(CONFIG_FILE)

############################
### DEFINIZIONE FUNZIONI ###
############################

### Funzione che controlla la presenza del file di configurazione ###
def ControlConfigFile():
    try:
        f = open(CONFIG_FILE,'r')
        logger.info("Verifica file di configurazione andata a buon fine")
        f.close()
    except IOError:
        logger.error("Il file di configurazione non esiste, verificare. Esco!")
        sys.exit()

### prendo la data di ieri ###
def YesterdayDate():
    yesterday = date.today() - timedelta(TIME_DELTA)
    yesterday.strftime('%Y%M%D')

    return yesterday


##############################################################
### funzione che si occupa di prendere i dati dai file xml ###
##############################################################
def GetDataFromXml(xml_file, PATH):

    ### verifico che i file xml che arrivano dai client siano formalmente corretti ###
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        logger.info("il file xml "+xml_file+" e' corretto")
    except IOError:
        logger.error("il file "+xml_file+" non e' correto")

    try:
        for parent in root:
            if parent.tag == 'server':
                SERVER_SENDER = parent.get('name')

            for child in parent:
                if child.tag == 'file':
                    FILE_NAME = child.get('name')
                    FILE_SIZE = child.find('size').text
                    FILE_MD5 = child.find('md5sum').text
                    FILE_DATE = child.find('file_date').text

                    ### inserisco i dati dei file mandati dai client ###
                    FILE_INSERT_DATE = time.strftime("%Y-%m-%d %H:%M:%S")
                    DB_InsertClientFile(FILE_DATE, FILE_NAME, SERVER_SENDER, FILE_MD5, FILE_SIZE, FILE_INSERT_DATE, PATH)

    except UnboundLocalError:
        logger.error("il file "+xml_file+" non esiste")

        ### TRAP ###
        SendNagiosTrap("errore il file xml non esiste")


#########################################################################################
### funzione principale che mi permette di processari i file e caricare i dati sul DB ###
#########################################################################################
def FileElaboration(path_file_fs, yesterday_dd, key, storage_end, path_integrity_violation, PATH):
    cont = 0
    insert_xml_verify = 0

    try:
        ### ciclo sulla lista di file nella dir dei server ###
        for file in os.listdir(path_file_fs):

            ### cerco tutti i file della data interessata ###
            if fnmatch.fnmatch(file, '*'+str(yesterday_dd)+'*.gz'):

                ### applico l'md5 sui file gz presenti n locale ###
                md5 = hashlib.md5()
                try:
                    f = open(path_file_fs+file,'rb')
                    for chunk in iter(lambda: f.read(8192), b''):
                        md5.update(chunk)

                    md5_file_hash = md5.hexdigest()
                    f.close()

                    ### verifico i dati dal DB per l'md5 dei file ###
                    DB_md5 = DB_SelectMd5(file)

                    ### faccio i test di integrita' per tutti i file ###
                    if DB_md5 == md5_file_hash:
                        logger.info("test di integrita' superato per il file "+file)

                        ### inizio con la fase di crittografia dei file ###
                        EncryptFile(key, path_file_fs+file)

                        ### sposto i file su storage finale ###
                        try:
                            shutil.copy(path_file_fs+file+"_AES_CBC.crypt", storage_end)
                            logger.info("sposto il file "+file+" su storage "+storage_end)

                            ### cancello i files dopo averli crittografati e spostati su storage ###
                            try:
                                ### cancello i file scaricati dai client ###
                                os.remove(path_file_fs+file)
                                logger.info("cancello il file "+path_file_fs+file)

                            except (IOError, os.error) as rem:
                                logger.error("errore non riesco a cancellare il file : "+file+" "+rem)

                                ### TRAP ###
                                SendNagiosTrap("errore non riesco a cancellare il file")

                            try:
                                ### cancello tutti i file crittografati ###
                                os.remove(path_file_fs+file+"_AES_CBC.crypt")
                                logger.info("cancello il file "+path_file_fs+file+"_AES_CBC.crypt")

                            except (IOError, os.error) as rem1:
                                logger.error("errore non riesco a cancellare il file : "+file+"_AES_CBC.crypt "+rem1)

                                ### TRAP ###
                                SendNagiosTrap("errore non riesco a cancellare il file")

                            ### faccio update su DB per mettere lo stato del file ###
                            DB_UpdateState(file,"done")

                        except (IOError, os.error) as dd:
                            logger.error("non sono riuscito a copiare il file "+path_file_fs+file+" sullo storage "+storage_end+" "+dd)

                            ### TRAP ###
                            SendNagiosTrap("ERRORE copia file storage end")
                    else:
                        ### sposto i file che non hanno passato il test di integrita' su una directory definita ###
                        try:
                            shutil.copy(path_file_fs+file, path_integrity_violation)
                            logger.error("test di integrita' NON passato sposto il file "+path_file_fs+file+" nella directory "+path_integrity_violation)

                        except (IOError, os.error) as why:
                            logger.error("errore copia file violation "+file+" nella directory "+path_integrity_violation+"  "+why)

                            ### TRAP ###
                            SendNagiosTrap("ERRORE copia file violation")

                        ### update stato processamento file ###
                        DB_UpdateState(file,"error")

                    cont = 0

                except IOError:
                    logger.error("non riesco ad aprire il file"+path_file_fs+file)
                    ### TRAP ###
                    SendNagiosTrap("ERRORE non riesco ad aprire il file")

            elif fnmatch.fnmatch(file, '*'+str(yesterday_dd)+'*.xml'):

                ### applico l'md5 sul file xml presente in locale ###
                md5_xml = hashlib.md5()
                try:
                    ca = open(path_file_fs+file,'rb')
                    for chunk1 in iter(lambda: ca.read(8192), b''):
                        md5_xml.update(chunk1)

                    xml_md5_file_hash = md5_xml.hexdigest()
                    ca.close()

                    ### inserisco il file xml su apposita tabella ###
                    FILE_INSERT_DATE = time.strftime("%Y-%m-%d %H:%M:%S")
                    try:
                        stat_file_xml = os.stat(path_file_fs+file)

                        DB_InsertXml(file, xml_md5_file_hash, str(stat_file_xml[ST_SIZE]), FILE_INSERT_DATE, PATH)

                        ### faccio la insert sulla tabella xml_file_list ###
                        if insert_xml_verify == 0:

                            ### inizio con la fase di crittografia dei file ###
                            EncryptFile(key, path_file_fs+file)

                            ### faccio la marcatura temporale per il file indice giornaliero ###
                            print(path_file_fs,file+"_AES_CBC.crypt")
                            GetTimestamp(path_file_fs,file+"_AES_CBC.crypt")

                            ### copio il file su storage finale ###
                            try:
                                shutil.copy(path_file_fs+file+"_AES_CBC.crypt", storage_end)
                                logger.info("copio il file indice xml : "+file+" sullo storage")

                                ### cancello il file xml ###
                                try:
                                    os.remove(path_file_fs+file)
                                    logger.info("cancecllo il file : "+file)
                                except (IOError, os.error) as rem3:
                                    logger.error("errore non riesco a cancellare il file : "+file+" "+rem3)

                                ### cancello il file xml crittografato ###
                                try:
                                    os.remove(path_file_fs+file+"_AES_CBC.crypt")
                                    logger.info("cancecllo il file crittografato : "+file+"_AES_CBC.crypt")

                                except (IOError, os.error) as rem4:
                                    logger.error("errore non riesco a cancellare il file : "+file+"_AES_CBC.crypt "+rem4)

                            except (IOError, os.error) as xx:
                                logger.error("non riesco a copiare il file "+path_file_fs+file+" nello storage "+str(xx))

                            ### copio il file tar con marcatura temporale ###
                            try:
                                shutil.copy(path_file_fs+file+"_AES_CBC.crypt-ts.tar.gz", storage_end)
                                logger.info("copio il tar indice xml : "+file+"_AES_CBC.crypt-ts.gz sullo storage")

                                ### cancello il file tar tsr con marcatura temporale dalla path temporanea ###
                                try:
                                    os.remove(path_file_fs+file+"_AES_CBC.crypt-ts.tar.gz")
                                    logger.info("cancello il file : "+file+"_AES_CBC.crypt-ts.gz")

                                except (IOError, os.error) as rem5:
                                    logger.error("errore non riesco a cancellare il file : "+file+"_AES_CBC.crypt-ts.gz"+str(rem5))

                                ### cancello il fil tsr dalla directory temporanea ###
                                try:
                                    os.remove(path_file_fs+file+"_AES_CBC.crypt.tsr")
                                    logger.info("cancello il file tsr : "+file+"_AES_CBC.crypt.tsr")

                                except (IOError, os.error) as rem6:
                                    ogger.error("non riesco a cancellare il file : "+file+"_AES_CBC.crypt.tsr")

                            except (IOError, os.error) as rem7:
                                logger.error("non riesco a copiare il file "+file+"_AES_CBC.crypt-ts.gz nello storage "+str(rem7))

                        else:
                            logger.error("problemi di elaborazione con il file : "+file)

                            ### TRAP ###
                            SendNagiosTrap("problemi di elaborazione con il file")

                    except IOError:
                        logger.error("non riesco a prendere la size del file : "+path_file_fs+file)

                        ### TRAP ###
                        SendNagiosTrap("non riesco a prendere la size del file")


                    cont = 0

                except Exception, md5_err:
                    logger.error("non riesco a fare l'md5 sul file "+file+" "+str(md5_err))

                    ### TRAP ###
                    SendNagiosTrap("non riesco a fare l'md5 sul file ")

            else:
                logger.error("Il file "+file+" non e' presente su optiserver")
                cont += 1

        if cont > 0:
            logger.error("Non sono presenti i file con la data cercata "+str(yesterday_dd))
            ### TRAP ###
            SendNagiosTrap("Non sono presenti i file con la data cercata")


    except OSError:
        logger.error("La directory dove sono presenti i file dei client "+path_file_fs+" e' inesistente")


########################################################
### funzione che mi permette di crittografare i file ###
########################################################
def EncryptFile(key, in_filename, out_filename=None, chunksize=64*1024):

    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>_AES_CBC.crypt' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """

    ### faccio la verifica prima di crittografare un file che sia maggiore di 0 bite ###
    test_file_not_zero = os.stat(in_filename)

    if test_file_not_zero[ST_SIZE] != 0:

        if not out_filename:
            out_filename = in_filename+"_AES_CBC.crypt"

        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(in_filename)

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                while True:
                    try:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - len(chunk) % 16)
                    except:
                        logger.error("chunk del file "+chunk+" andata male")

                        ### TRAP ###
                        SendNagiosTrap("chunk del file andata male")

                    outfile.write(encryptor.encrypt(chunk))

            logger.info("cripto il file "+out_filename)

    else:
        logger.error("il file "+in_filename+" e' uguale a 0")

        ### TRAP ###
        SendNagiosTrap("il file e' uguale a 0")


#################################################################################
### Controllo l'esistenza delle dir sulla path di work e sullo storage finale ###
#################################################################################
def CheckDirectory(path_storage_directory):
    try:
        ### verifico se esiste dir di storage ###
        if os.path.exists(path_storage_directory):
            logger.info("verifica della directory di storage "+path_storage_directory+" andata a buon fine")
        else:
            logger.info("directory "+path_storage_directory+" non presente")
            ### se non esiste la creo ###
            try:
                os.makedirs(path_storage_directory)
                logger.info("directory creata")
            except:
                logger.error("non riesco a creare la directory "+path_storage_directory)

                ### TRAP ###
                SendNagiosTrap("non riesco a creare la directory")

    except:
        logger.error("errore non posso verificare se esiste la dir "+path_storage_directory)


#########################
### Connessione al DB ###
#########################
def DB_InsertClientFile(FILE_DATE, FILE_NAME, ORIGIN, MD5, SIZE, FILE_INSERT_DATE, PATH):
    try:
        conn = psycopg2.connect(CONNECT_STRING)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO CONSOST.FILE_LIST (file_date, file_name, origin, md5sum, size, file_insert_date, path_crypt_file) VALUES ('"+FILE_DATE+"','"+FILE_NAME+"','"+ORIGIN+"','"+MD5+"','"+SIZE+"','"+FILE_INSERT_DATE+"','"+PATH+"')")
            cur.close()

            ### faccio la commit e chiudo la connessione ###
            conn.commit()
            conn.close()

        except Exception, db_insert:
            logger.error("Data Base insert failure"+str(db_insert))

            ### TRAP ###
            SendNagiosTrap("DB insert failure")

            ### Esco dal programma ###
            sys.exit(1)

    except Exception, ee:
        logger.error("errore di connessione al DB :"+str(ee))

        ### TRAP ###
        SendNagiosTrap("errore di connessione al DB")

        ### Esco dal programma ###
        sys.exit(1)


##############################################################################################
### funzione che serve a fare il confronto tra md5 dei file scaricati e quello all'origine ###
##############################################################################################
def DB_SelectMd5(FIILE):
    try:
        conn1 = psycopg2.connect(CONNECT_STRING)
        cur1 = conn1.cursor()
        try:
            cur1.execute("SELECT * FROM CONSOST.FILE_LIST WHERE file_name = '"+FIILE+"'")
            rows1 = cur1.fetchall()
            for row in rows1:
                if row[5] != 0:
                    DB_md5 = row[4]
                    logger.info("sul DB l'md5 per il il file "+row[2]+" e' : "+row[4])
                    return(DB_md5)

                else:
                    logger.error("il file "+row[1]+" ha dimensioni a 0 bite")
                    return 0

        except:
            logger.error("Non riesco a fare la select")

            ### TRAP ###
            SendNagiosTrap("errore non riesco a fare select")

    except Exception, oracle_err:
        logger.error(oracle_err)

        ### TRAP ###
        SendNagiosTrap("errore di connessione al DB")


##########################################################
### funzione che aggiorna lo stato del processo sul DB ###
##########################################################
def DB_UpdateState(file, proc_status):
    try:
        conn2 = psycopg2.connect(CONNECT_STRING)
        cur2 = conn2.cursor()
        try:
            cur2.execute("UPDATE CONSOST.FILE_LIST SET PROCESS_STATE = '"+proc_status+"' WHERE FILE_NAME = '"+file+"'")
            cur2.close()

            ### faccio la commit e chiudo la connessione ###
            conn2.commit()
            conn2.close()

        except:
            logger.error("Data Base update failure")

            ### TRAP ###
            SendNagiosTrap("Data Base update failure")

    except Exception, err:
        logger.error("connessione al DB non avvenuta "+str(err))

        ### TRAP ###
        SendNagiosTrap("errore di connessione al DB")


########################################################
### Inserisco i file dontro la tabella XML_FILE_LIST ###
########################################################
def DB_InsertXml(FILE_NAME, MD5, SIZE, FILE_INSERT_DATE, PATH):
    try:
        conn3 = psycopg2.connect(CONNECT_STRING)
        cur3 = conn3.cursor()

        try:
            cur3.execute("INSERT INTO CONSOST.XML_FILE_LIST (xml_file_name, md5sum, size, file_insert_date, path_crypt_file) VALUES ('"+FILE_NAME+"','"+MD5+"','"+SIZE+"','"+FILE_INSERT_DATE+"','"+PATH+"')")
            cur3.close()

            ### faccio la commit e chiudo la connessione ###
            conn3.commit()
            conn3.close()

            logger.info("eseguo la insert nella tabella XML_FILE_LIST")

            insert_xml_verify = 0

        except Exception, xml_err:
            logger.error("Data Base xml insert failure "+str(xml_err))

            ### TRAP ###
            SendNagiosTrap("Data Base xml insert failure")

            insert_xml_verify = 1

    except Exception, con_err:
        logger.error("connessione al DB non avvenuta "+str(con_err))

        ### TRAP ###
        SendNagiosTrap("errore di connessione al DB")

        insert_xml_verify = 1

    return insert_xml_verify


###########################################################################################################
### funzione che mi permette di costruire il file indice in formato xml prendendo i dati mensili dal DB ###
###########################################################################################################
def DB_GenerateMonthIndex(ymonthyear):
    try:
        ### istanzio oggetti per la connessione ###
        connG = psycopg2.connect(CONNECT_STRING)
        curG = connG.cursor()

        ### creo l'oggetto xml ###
        file_index = ET.Element("file_index")
        tree = ET.ElementTree(file_index)

        try:
            ### eseguo query ###
            curG.execute("SELECT FILE_NAME, MD5SUM, SIZE, FILE_INSERT_DATE from CONSOST.FILE_LIST WHERE FILE_NAME LIKE '%"+ymonthyear+"%'")

            logger.info("costruisco il file indice index_file_"+ymonthyear)

            ### raccolgo i dati che mi interessano ###
            for rw in curG:
                logger.info("file : "+str(rw[0])+", md5sum : "+str(rw[1])+", size : "+str(rw[2])+", file_insert_date : "+str(rw[3]))

                file = ET.SubElement(file_index, "file")
                file.set("name", rw[0])

                md5sum = ET.SubElement(file, "md5sum")
                md5sum.text = rw[1]

                size = ET.SubElement(file, "size")
                size.text = str(rw[2])

                date_insert_db = ET.SubElement(file, "date_insert_db")
                date_insert_db.text = str(rw[3])

            ### faccio la commit e chiudo le connessioni ###
            curG.close()
            connG.commit()
            connG.close()

            ### concludo l'xml indentandolo e rendendolo piu' leggibile ###
            lXml = ET.tostring(tree.getroot(),'utf-8')
            lXml = "<?xml version='1.0' encoding='utf-8'?>\n%s" % lXml
            data = xml.dom.minidom.parseString(lXml)
            output_file = open(PATH_INDEX_MONTHLY+'file-index-monthly-'+ymonthyear+'.xml', 'w')
            xml.dom.ext.PrettyPrint(data, output_file)
            output_file.close()

        except Exception, errMonth:
            logger.error("Data Base monthly index generator failure "+str(errMonth))

            ### TRAP ###
            SendNagiosTrap("Data Base monthly index generator failure")

    except Exception, err:
        logger.error("connessione al DB non avvenuta "+str(err))

        ### TRAP ###
        SendNagiosTrap("errore di connessione al DB")


#############################################################
### Funzione che mi permette di inviare una trap a Nagios ###
#############################################################
def SendNagiosTrap(mess):
    subprocess.Popen('echo "optiserver*invio trap cons_sost_new-X.X.py*2*'+mess+'"|'+NSCA_PATH+'bin/send_nsca  -H '+IP_NAGIOS+' -d \"*\" -c '+NSCA_PATH+'bin/send_nsca.cfg', shell=True)


####################################################################################
### Funzione che mi permette di prendere la password per fare l'encrypt dei file ###
####################################################################################
def DB_GetKeyPassword():
    key = 0
    try:
        conn4 = psycopg2.connect(CONNECT_STRING)
        cur4 = conn4.cursor()

        try:
            cur4.execute("SELECT PASSWORD FROM CONSOST.PASSWORD WHERE ID_PASSWORD = 'key_crypt' ")

            Password_key = cur4.fetchone()[0]

            cur4.close()

            print(Password_key)
            h = SHA256.new()
            h.update(Password_key)
            key = h.hexdigest()

            logger.info("recuparata la password per crittografare i file")

        except Exception, pwd_err:
            logger.error("password unknown "+str(pwd_err))

            ### TRAP ###
            SendNagiosTrap("errore password unknown")

    except Exception, con4_err:
        logger.error("connessione al DB non avvenuta "+str(con4_err))

        SendNagiosTrap("errore di connessione al DB")

    return key


###############################################################
### funzione che appone il time stamp al file lista mensile ###
###############################################################
def GetTimestamp(path_file, file_origin):

    try:
        ### Faccio la richiesta TimeStamp per il file che devo processare ###
        subprocess.check_call(OPENSSL+' ts -query -data '+path_file+file_origin+' -cert -sha256 -policy '+TS_POLICY+' -no_nonce -out '+PATH_RQST+file_origin+'.tsq', shell=True)

        ### costruisco il comando in bash con curl ###
        cmd = CAT+" "+PATH_RQST+file_origin+".tsq | "+CURL+" -s -S -k -H 'Content-Type: application/timestamp-query' -u "+TS_USER+":"+TS_PWD+" --data-binary @- "+TS_URL+" -o "+path_file+file_origin+".tsr"

        cmd.split()
        try:
            ### spedisco la richiesta al server Trusted TS via https ###
            subprocess.check_call(cmd, shell=True)
            logger.info("eseguo la richiesta di marcatura temporale per il file :"+file_origin)

            try:
                ### faccio la verifica della marcatura temporale richiesta con il file originale ###
                subprocess.check_call(OPENSSL+' ts -verify -data '+path_file+file_origin+' -in '+path_file+file_origin+'.tsr -CAfile '+PATH_CERTIFICATE+CA_CERT, shell=True)
                logger.info("verifica della marcatura temporale andata a buon fine per il file : "+file_origin)

                ### costruisco il tar contenente il file originale e la marca temporale ###
                try:
                    subprocess.check_call(TAR+' cvf '+path_file+file_origin+'-ts.tar '+path_file+file_origin+' '+path_file+file_origin+'.tsr', shell=True)
                    logger.info("faccio il tar dei file : "+file_origin+" e "+file_origin+".tsr")

                    ### faccio il gzip del tar appena costruito ###
                    try:
                        subprocess.check_call(GZIP+' -f '+path_file+file_origin+'-ts.tar', shell=True)
                        logger.info("faccio il gzip del file : "+path_file+file_origin+"-ts.tar")

                    except subprocess.CalledProcessError as gziperr:
                        logger.error("non riesco a fare il gzip del tar : "+path_file+file_origin+"-ts.tar"+str(gziperr))

                except subprocess.CalledProcessError as tarerr:
                     logger.error("non riesco a fare il tar dei file : "+file_origin+" e "+file_origin+".tsr"+str(tarerr))

            except subprocess.CalledProcessError as verifyerr:
                logger.error("verifica della maratura temporale andata male per il file : "+file_origin+" "+str(verifyerr))


        except subprocess.CalledProcessError as subproc_err:
            logger.error("timestamps andata male per il file : "+file_origin+" "+str(subproc_err)+" riprovo...")

            ### riprovo a fare la marcatura temporale per la seconda volta ###
            try:
                subprocess.check_call(cmd, shell=True)
                logger.info("Secondo tentativo richiesta di marcatura temporale per il file :"+file_origin+" eseguita")

                try:
                    ### faccio la verifica della marcatura temporale richiesta con il file originale ###
                    subprocess.check_call(OPENSSL+' ts -verify -data '+path_file+file_origin+' -in '+path_file+file_origin+'.tsr -CAfile '+PATH_CERTIFICATE+CA_CERT, shell=True)
                    logger.info("verifica della marcatura temporale andata a buon fine per il file : "+file_origin)

                    ### costruisco il tar contenente il file originale e la marca temporale ###
                    try:
                        subprocess.check_call(TAR+' cvf '+path_file+file_origin+'-ts.tar '+path_file+file_origin+' '+path_file+file_origin+'.tsr', shell=True)
                        logger.info("faccio il tar dei file : "+file_origin+" e "+file_origin+".tsr")

                        ### faccio il gzip del tar appena costruito ###
                        try:
                            subprocess.check_call(GZIP+' -f '+path_file+file_origin+'-ts.tar', shell=True)
                            logger.info("faccio il gzip del file : "+path_file+file_origin+"-ts.tar")

                        except subprocess.CalledProcessError as gziperr:
                                logger.error("non riesco a fare il gzip del tar : "+path_file+file_origin+"-ts.tar"+str(gziperr))

                    except subprocess.CalledProcessError as tarerr:
                        logger.error("non riesco a fare il tar dei file : "+file_origin+" e "+file_origin+".tsr"+str(tarerr))

                except subprocess.CalledProcessError as verifyerr:
                    logger.error("verifica della maratura temporale andata male per il file : "+file_origin+" "+str(verifyerr))

            except subprocess.CalledProcessError as subproc_err:
                logger.error("timestamps andata male per la seconda volta per il file : "+file_origin+" "+str(subproc_err))

    except subprocess.CalledProcessError as errorRqst:
        logger.error("non riesco a fare la request di timestamp per il file : "+file_origin+" "+str(errorRqst))


#################################################################################################
### funzione che mi permette di verificare il primo giorno del mese per creare il file indice ###
#################################################################################################
def ChekFirstDayOfMonth(yest_day, key):
    to_day = date.today()
    day = to_day.strftime('%d')
    ### yday = yest_day.strftime('%d')
    if day == FIRST_DAY_OF_MONTH :
        ymonthyear = yest_day.strftime('%Y-%m')
        logger.info("lancio la genarazione del file indice mensile")

        ### faccio estrazione sul DB per il mese interessato ###
        DB_GenerateMonthIndex(ymonthyear)

        ### critto il file index mensile generato ###
        EncryptFile(key, PATH_INDEX_MONTHLY+'file-index-monthly-'+ymonthyear+'.xml')

        try:
            os.remove(PATH_INDEX_MONTHLY+"file-index-monthly-"+ymonthyear+".xml")
            logger.info("cancello il file "+PATH_INDEX_MONTHLY+"file-index-monthly-"+ymonthyear+".xml")

        except (IOError, os.error) as rmym:
            logger.error("non riesco  cancellare il file : "+PATH_INDEX_MONTHLY+"file-index-monthly-"+ymonthyear+".xml"+str(rmym))

        ### eseguo la marcatura temporale del file indice mensile ###
        GetTimestamp(PATH_INDEX_MONTHLY, "file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt")

        try:
            os.remove(PATH_INDEX_MONTHLY+"file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt")
            logger.info("cancello il file indice mensile crittografato : file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt")

        except (IOError, os.error) as rmxmlcrypt:
            logger.error("non riesco a cancellare il file indice mensile crittografato : file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt"+str(rmxmlcrypt))

        ###cancello la marca temporale per il file indice mensile ###
        try:
            os.remove(PATH_INDEX_MONTHLY+"file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt.tsr")
            logger.info("la marca temporale per il file indice mensile : file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt.tsr")

        except (IOError, os.error) as rmxmlcrypttsr:
            logger.error("non riesco marca temporale per il file indice mensile : file-index-monthly-"+ymonthyear+".xml_AES_CBC.crypt.tsr"+str(rmxmlcrypttsr))


############
### MAIN ###
############

if __name__ == "__main__":

    ### Prendo la password per crittografare i file ###
    key = DB_GetKeyPassword()

    ### controlla che il file di configurazione esiste ###
    ControlConfigFile()
    yesterday_dd = YesterdayDate()

    ChekFirstDayOfMonth(yesterday_dd, key.decode('hex'))

    ### ciclo principale Leggo il file di configurazione ###
    for name_section in parser.sections():
        if parser.getboolean(name_section,'active') == True:
            ### controllo il file xml arrivato e inserisco sul DB i dati ###
            GetDataFromXml(parser.get(name_section,'path_download')+'file_inviati_'+parser.get(name_section,'server_name')+'_'+str(yesterday_dd)+'.xml', parser.get(name_section,'storage_end'))

            ### verifico che le dir siano esistenti ###
            CheckDirectory(parser.get(name_section,'storage_end'))

            ### inizio l'elaborazione dei file ###
            FileElaboration(parser.get(name_section,'path_download'),yesterday_dd, key.decode('hex'), parser.get(name_section,'storage_end'), PATH_INTEGRITY_VIOLATION, parser.get(name_section,'storage_end'))

        else:
            logger.warning("il server "+parser.get(name_section,'server_name')+" non e' attivo")
