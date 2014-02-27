<?php
class accountSystem{

    private $dbName;
    private $host;
    private $username;
    private $password;

    //the constructor will
    function __construct($dbName, $host = 'localhost', $username = 'root', $password = '') {
        $this->dbName = $dbName;
        $this->host = $host;
        $this->username = $username;
        $this->password = $password;
        session_start();
    }

    //this will create a table if there is no table already. This only has to be ran once.
    function createTable() {
        $createTable = "
        CREATE TABLE IF NOT EXISTS `users` (
            `user_id` int(11) NOT NULL AUTO_INCREMENT,
            `username` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
            `password` char(64) COLLATE utf8_unicode_ci NOT NULL,
            `salt` char(16) COLLATE utf8_unicode_ci NOT NULL,
            `email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
        PRIMARY KEY (`user_id`),
        UNIQUE KEY `username` (`username`),
        UNIQUE KEY `email` (`email`)
        ) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1;";
        
        $stmt = $this->connectToDb($this->username, $this->password, $this->host, $this->dbName)->prepare($createTable);
        $stmt->execute();
    }

    //this connects to a database. 
    private function connectToDb(){
        try{ 
        // Opens DB connection.
            $db = new PDO("mysql:host={$this->host};dbname={$this->dbName};charset=utf8", $this->username, $this->password);
        }
        catch(PDOException $ex){ 
            die("Failed to connect to the database."); 
        }
        return $db;
    }

    //Executes a query with parameters
    function executeQuery($query, $queryParams = ''){
        try{ 
            $stmt = $this->connectToDb()->prepare($query);
            if(isset($queryParams)){
                $stmt->execute($queryParams); 
            }else{
                $stmt->execute(); 
            }
        }catch(PDOException $ex){  
            die("Failed to run query."); 
        }
         
        return $stmt;
    }

    //this function will log a user in. Returns true if success and false if error
    function login($username, $password){
        $query = "SELECT 
                    user_id, 
                    username, 
                    password, 
                    salt, 
                    email
                FROM 
                    users
                WHERE username = :username";
        $queryParams = array(':username' => $username);

        $stmt = $this->executeQuery($query, $queryParams);
        $login_ok = false;
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if($row) 
        { 
            $check_password = hash('sha256', $password . $row['salt']);
            for($round = 0; $round < 65536; $round++) 
            { 
                $check_password = hash('sha256', $check_password . $row['salt']); 
            } 
             
            if($check_password === $row['password']) 
            { 
                $login_ok = true; 
            } 
        }
        if($login_ok) 
        {
            unset($row['salt']);
            unset($row['password']);
            $_SESSION['user'] = $row; 
        }
        return $login_ok;
    }

    //this function will log a user out
    function logout(){
        unset($_SESSION['user']);
    }

    //this function will register a user. If the email already exists then it will return a 4
    //if the username already exists it will return a 3 if all was successful it will return a 2
    function register($username, $email, $password){
        $usernameExists = false;
        $emailExists = false;
        $query = "
            SELECT
                1
            FROM users
            WHERE
                username = :username
        ";
        $queryParams = array(
            ':username' => $username
        );

        $stmt = $this->executeQuery($query, $queryParams);
        $row = $stmt->fetch();
        if($row)
        {
            $usernameExists = true;
        }
        $query = "
            SELECT
                1
            FROM users
            WHERE
                email = :email
        ";
        $queryParams = array(
            ':email' => $_POST['email']
        );
        $stmt = $this->executeQuery($query, $queryParams);
        $row = $stmt->fetch();
        if($row)
        {
            $emailExists = true;
        }
        if($emailExists){
            $return = 4;
        }
        else if($usernameExists){
            $return = 3;
        }else{
            $query = "
            INSERT INTO users (
                username,
                password,
                salt,
                email
            ) VALUES (
                :username,
                :password,
                :salt,
                :email
            )
            ";
            $salt = dechex(mt_rand(0, 2147483647)) . dechex(mt_rand(0, 2147483647));
            $password = hash('sha256', $password . $salt);
            for($round = 0; $round < 65536; $round++)
            {
                $password = hash('sha256', $password . $salt);
            }
            $queryParams = array(
                ':username' => $username,
                ':password' => $password,
                ':salt' => $salt,
                ':email' => $email
            );
            $this->executeQuery($query, $queryParams);
            $return = 2;
        }
        return $return;
    }

    //check to see if user is logged in or not returns boolean
    function checkLoginStatus(){
        if(empty($_SESSION['user'])){
            $loggedIn = false;
        }else{
            $loggedIn = true;
        }
        return $loggedIn;
    }
}
