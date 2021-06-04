module model;

///User
class User {
    int id; /// User ID
    string username; /// Username
    string password_salt; /// Password Salt
    string password_hash; /// Password Hash
    string email; /// Email
    string last_ip; /// Last IP
}