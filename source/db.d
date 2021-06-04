module db;

import model;
import taskdesigns.sqlite;
import arsd.sqlite;
import std.array;
import std.stdio;
import std.conv;

/++ Database Interface
 - Allows us to abstract database calls if we change database types from a SQL (Relational Database) or NoSQL (Non-relational database)
++/
interface DB {
    /// Insert User
    void insertUser(User user);
    /// Get User
    User getUser(string username);
}

///User Table
struct UserTable {
    Table table = new Table( "users"); /// Table name
    Column!int id = new Column!int( "id", false); /// ID
    Column!string username = new Column!string( "username", false); /// Username
    Column!string password_hash = new Column!string( "password_hash", false); /// Password Hash
    Column!string email = new Column!string( "email", false); /// Email
    Column!string last_ip = new Column!string( "last_ip", false); /// Last IP
}

/// User Database
class UserDB: DB {
    Database db; /// SQLite Database

    /// Constructor
    this(string dbName = "data") {
        db = new Sqlite( dbName~".db");
        createUserTable();
    }

    /// Create User Table
    private void createUserTable(bool requiresDrop = false) {
        if (requiresDrop)
            db.query( UserTable().table.drop().asSQL());
        db.query( UserTable().table.create( (it) {
            auto table = UserTable();
            it.column( table.id, true, false, true);
            it.column( table.username);
            it.column( table.password_hash);
            it.column( table.email);
            it.column( table.last_ip);
        }).asSQL());
    }

    override void insertUser(User user) {
        auto user_table = UserTable().table;
        void s (Setters it) {
            auto table = UserTable();
            if (!user.username.empty()) {
                it[table.username] = user.username;
            }
            if (!user.password_hash.empty()) {
                it[table.password_hash] = user.password_hash;
            }
            if (!user.email.empty()) {
                it[table.email] = user.email;
            }
            if (!user.last_ip.empty()) {
                it[table.last_ip] = user.last_ip;
            }
        }
        string sql = user_table.insertOrReplace( &s).asSQL();
        db.query( sql);
    }

    /// Function to map the database row to a User object.
    private User getUser(Row result) {
        User user = new User();
        user.id = to!int( result[0]);
        user.username = result[1];
        user.password_hash = result[2];
        user.email = result[3];
        user.last_ip = result[4];
        return user;
    }

    override User getUser(string username) {
        User user = null;
        auto user_table = UserTable();
        foreach (result; db.query( user_table.table.select().where( user_table.username.eq( username)).asSQL())) {
            user = getUser( result);
        }
        return user;
    }
}