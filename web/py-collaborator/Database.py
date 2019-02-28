#!/usr/bin/python3

import pymysql
import pymysql.cursors
import pymysql.converters

from Logger import *
import datetime

DATABASE_LOGGING = False

class Logger:
    @staticmethod
    def _out(x):
        if DATABASE_LOGGING:
            sys.stderr.write(str(x) + u'\n')

    @staticmethod
    def dbg(x):
        if DATABASE_LOGGING:
            sys.stderr.write(u'[dbg] ' + str(x) + u'\n')

    @staticmethod
    def out(x):
        Logger._out(u'[.] ' + str(x))

    @staticmethod
    def info(x):
        Logger._out(u'[?] ' + str(x))

    @staticmethod
    def err(x):
        if DATABASE_LOGGING:
            sys.stderr.write(u'[!] ' + str(x) + u'\n')

    @staticmethod
    def warn(x):
        Logger._out(u'[-] ' + str(x))

    @staticmethod
    def ok(x):
        Logger._out(u'[+] ' + str(x))


class Database:
    databaseConnection = None
    databaseCursor = None
    lastUsedCredentials = {
        'host': '',
        'user': '',
        'password': '',
        'db': ''
    }

    def __init__(self, initialId = 1000):
        self.queryId = initialId
        pass

    def __del__(self):
        self.close()

    def close(self):
        Logger.dbg("Closing database connection.")
        if self.databaseConnection: self.databaseConnection.close()
        self.databaseConnection = None

    def connection(self, host, user, password, db = None):
        try:
            conv = pymysql.converters.conversions.copy()
            conv[246] = float
            conv[0] = float

            if password:
                self.databaseConnection = pymysql.connect(
                    host=host,
                    user=user,
                    passwd=password,
                    db=db,
                    cursorclass=pymysql.cursors.DictCursor,
                    conv = conv
                )
            else:
                self.databaseConnection = pymysql.connect(
                    host=host,
                    user=user,
                    db=db,
                    cursorclass=pymysql.cursors.DictCursor,
                    conv=conv
                )

            #self.databaseConnection.set_character_set('utf8')

            Logger.info("Database connection succeeded.")

            self.lastUsedCredentials.update({
                'host': host,
                'user': user,
                'password': password,
                'db': db
            })

            return True

        except (pymysql.Error, pymysql.Error) as e:
            Logger.err("Database connection failed: " + str(e))
            return False

    def createCursor(self):
        if self.databaseCursor:
            self.databaseCursor.close()
            self.databaseCursor = None

        if not self.databaseConnection:
            self.reconnect()

        self.databaseCursor = self.databaseConnection.cursor()
        # self.databaseCursor.execute('SET CHARACTER SET utf8;')
        # self.databaseCursor.execute('SET NAMES utf8;')
        # self.databaseCursor.execute('SET character_set_connection=utf8;')
        # self.databaseCursor.execute('SET GLOBAL connect_timeout=28800;')
        # self.databaseCursor.execute('SET GLOBAL wait_timeout=28800;')
        # self.databaseCursor.execute('SET GLOBAL interactive_timeout=28800;')
        # self.databaseCursor.execute('SET GLOBAL max_allowed_packet=1073741824;')
        return self.databaseCursor

    def query(self, query, tryAgain = False, params = None):
        self.queryId += 1
        if len(query)< 100:
            Logger.dbg(u'SQL query (id: {}): "{}"'.format(self.queryId, query))
        else:
            Logger.dbg(u'SQL query (id: {}): "{}...{}"'.format(self.queryId, query[:80], query[-80:]))

        try:
            self.databaseCursor = self.createCursor()
            if params:
                self.databaseCursor.execute(query, args = params)
            else:
                self.databaseCursor.execute(query)
            
            result = self.databaseCursor.fetchall()

            num = 0
            for row in result:
                num += 1
                if num > 5: break
                if len(str(row)) < 100:
                    Logger.dbg(u'Query (ID: {}) ("{}") results:\nRow {}.: '.format(self.queryId, str(query), num) + str(row))
                else:
                    Logger.dbg(u'Query (ID: {}) is too long'.format(self.queryId))

            return result

        except (pymysql.err.InterfaceError) as e:
            pass
        except (pymysql.Error) as e:
            if Database.checkIfReconnectionNeeded(e):
                if tryAgain == False:
                    Logger.err("Query (ID: {}) ('{}') failed. Need to reconnect.".format(self.queryId, query))
                    self.reconnect()
                    return self.query(query, True)

            Logger.err("Query (ID: {}) ('{}') failed: ".format(self.queryId, query) + str(e))
            return False

    @staticmethod
    def checkIfReconnectionNeeded(error):
        try:
            return (("MySQL server has gone away" in error[1]) or ('Lost connection to MySQL server' in error[1]))
        except (IndexError, TypeError):
            return False

    def reconnect(self):
        Logger.info("Trying to reconnect after failure (last query: {})...".format(self.queryId))
        if self.databaseConnection != None:
            try:
                self.databaseConnection.close()
            except:
                pass
            finally:
                self.databaseConnection = None

        self.connection(
            self.lastUsedCredentials['host'],
            self.lastUsedCredentials['user'],
            self.lastUsedCredentials['password'],
            self.lastUsedCredentials['db']
        )

    def insert(self, query, tryAgain = False):
        '''
            Executes SQL query that is an INSERT statement.

        params:
            query   SQL INSERT query

        returns:
                (boolean Status, int AffectedRows, string Message)

            Where:
                Status          - false on Error, true otherwise
                AffectedRows    - number of affected rows or error code on failure
                Message         - error message on failure, None otherwise
        '''
        self.queryId += 1
        if len(query)< 100:
            Logger.dbg(u'SQL INSERT query (id: {}): "{}"'.format(self.queryId, query))
        else:
            Logger.dbg(u'SQL INSERT query (id: {}): "{}...{}"'.format(self.queryId, query[:80], query[-80:]))

        assert not query.lower().startswith('select '), "Method insert() must NOT be invoked with SELECT queries!"

        try:
            self.databaseCursor = self.createCursor()
            self.databaseCursor.execute(query)

            # Commit new records to the database

            self.databaseConnection.commit()
            return True, 1, None

        except (pymysql.Error, pymysql.Error) as e:
            try:
                # Rollback introduced changes
                self.databaseConnection.rollback()
            except: pass

            if Database.checkIfReconnectionNeeded(e):
                if tryAgain == False:
                    Logger.err("Insert query (ID: {}) ('{}') failed. Need to reconnect.".format(self.queryId, query))
                    self.reconnect()
                    return self.insert(query, True)

            Logger.err("Insert Query (ID: {}) ('{}') failed: ".format(self.queryId, query) + str(e))
            return False, e.args[0], e.args[1]

    def delete(self, query):
        assert query.lower().startswith('delete '), "Method delete() must be invoked only with DELETE queries!"
        return self.insert(query)
