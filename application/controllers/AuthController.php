<?php

require_once 'Zend/Controller/Action.php';

class AuthController extends Zend_Controller_Action
{
 
    public function loginAction()
    {
        $db = $this->_getParam('db');
 
        $loginForm = new Default_Form_Auth_Login();
 
        if ($loginForm->isValid($_POST)) {
 
            $adapter = new Zend_Auth_Adapter_DbTable(
                $db,
                'users',
                'username',
                'password',
                'MD5(CONCAT(?, password_salt))'
                );
 
            $adapter->setIdentity($loginForm->getValue('username'));
            $adapter->setCredential($loginForm->getValue('password'));
 
            $auth   = Zend_Auth::getInstance();
            $result = $auth->authenticate($adapter);
 
            if ($result->isValid()) {
                $this->_helper->FlashMessenger('Successful Login');
                $this->_redirect('/');
                return;
            }
 
        }
 
        $this->view->loginForm = $loginForm;
 
    }
	
	public function identifyAction()
	{
		if ($this->getRequest()->isPost()) {
			$formData = $this->_getFormData();
	if (empty($formData['username'])|| empty($formData['password'])) {
		$this->_flashMessage('Empty username or password.');
		}
	else {
	// do the authentication
		$authAdapter = $this->_getAuthAdapter($formData);
		$auth = Zend_Auth::getInstance();
		$result = $auth->authenticate($authAdapter);
		if (!$result->isValid()) {
			$this->_flashMessage('Login failed');
			}
		else {
		$data = $authAdapter->getResultRowObject(null,'password');
		$auth->getStorage()->write($data);
		$this->_redirect($this->_redirectUrl);
		return;
			}
		}
	}
	$this->_redirect('/auth/login');
	}
	
	protected function _getAuthAdapter($formData)
	{
		$dbAdapter = Zend_Registry::get('db');
		$authAdapter = new Zend_Auth_Adapter_DbTable($dbAdapter);
		$authAdapter->setTableName('users')
		->setIdentityColumn('username')
		->setCredentialColumn('password')
		->setCredentialTreatment('SHA1(?)');
		// get "salt" for better security
		$config = Zend_Registry::get('config');
		$salt = $config->auth->salt;
		$password = $salt.$formData['password'];
		$authAdapter->setIdentity($formData['username']);
		$authAdapter->setCredential($password);
		return $authAdapter;
	}
 
	public function logoutAction()
	{
		$auth = Zend_Auth::getInstance();
		$auth->clearIdentity();
		$this->_redirect('/');
	}
}
?>