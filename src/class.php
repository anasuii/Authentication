<?php
namespace Authentication;

class Authentication{
	static $loginPage = './login.php';
	static $defaultPage = './index.php';
	static $isPasswordHashed = false;
	static $hashAlgo = PASSWORD_DEFAULT;
	protected $userProvider;
	static $cookiesTimeout = 259000; /*Durata di default 30gg*/

	public function __construct($userProvider){
		// Salvo il provider della classe per manipolare i dati in un secondo momento
		if(isset($userProvider) && $userProvider instanceof UserProvider){
			$this->userProvider = $userProvider;
		}
	}

	public function login($username, $password, $rememberMe = false, $targetPage=null){	
		if(!(isset($username) && isset($password) && strlen($username)>0 &&isset($this->userProvider))){
			// Logoff per mancanza di dati
			Authentication::logout();
		}else{
			// Key-Value array con le informazioni dell'utente
			$userData = $this->userProvider->getUser($username);
			if(!(isset($userData) && $username == $userData['username'])){
				// Logoff per non corrispondenza dell'utente
				Authentication::logout();
			}else{
				// Controllo della password
				if(Authentication::$isPasswordHashed){
					$passwordChecked = hash($password, Authentication::$hashAlgo) === $userData['password'];
				}else{
					$passwordChecked = $password === $userData['password'];
				}
				
				if(!$passwordChecked){
					// Logoff per non corrispondenza della password
					Authentication::logout();
				}else{
					// Salvo i cookies per l'auto login
					if($rememberMe === true){
						$timeout = time() + Authentication::$cookiesTimeout;
						setcookie('username', $username, $timeout, '/');
						setcookie('password', $password, $timeout , '/');
					}
					
					// Avvio della sessione
					Authentication::startSession();
					
					// Mi salvo la variabile di sessione
					$_SESSION['username'] = $username;
					
					//Apro la pagina target (evito di andare in loop con il metodo custom)
					if(isset($targetPage)){
						header('location: '.$targetPage);
						//Authentication::redirect($targetPage);
					}
				}
			}
		}
	}

	static function redirect($target, $queryParams = null){
		if(isset($target)){
			if(isset($queryParams)){
				$target.='?'.$queryParams;
			}

			header('location: '.$target);
		}
	}

	static function checkLogin(){
		// Riprendo la sessione corrente
		Authentication::startSession();

		// Controllo l'esistenza della sessione
		if(!(Authentication::isSessionActive() && isset($_SESSION['username']))){
			Authentication::logout();
		}
	}

	public function autologin(){
		// Eseguo la procedura di login prendendo i dati dai cookies
		if(isset($_COOKIE['username']) && isset($_COOKIE['password'])){
			// Setto il remember me a true per rinnorave i cookies
			$this->login($_COOKIE['username'],$_COOKIE['password'], true, Authentication::$defaultPage);
		}
	}



	static function logout($queryParams = null){
		if(isset($_COOKIE)){
			// Pulizia dei cookies
			$timeout = time() - 36000;
			setcookie('username', '', $timeout ,'/');
			setcookie('password', '', $timeout, '/');
		}
		
		// Riprendo la sessione in corso
		Authentication::startSession();

		// Cancellazione della sessione
		session_destroy();
		
		// Reindirizzamento
		Authentication::redirect(Authentication::$loginPage, $queryParams);
	}

	static function isSessionActive(){
		return session_status() == PHP_SESSION_ACTIVE;	
	}

	static function startSession(){
		if(!Authentication::isSessionActive()){
			session_start();
		}
	}
}

interface UserProvider{
	 public function getUser($username);	
}

?>
