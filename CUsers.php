<?php

/* 
User handling class for PHP.
Copyright (C) 2010 Aleksi Räsänen <aleksi.rasanen@runosydan.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

error_reporting( E_ALL );

	// *******************************************
	//	CUsers
	/*!
		@brief User handling class for PHP. This class
		  is used when we want to know user information
		  or when we want to check login etc.

		@author Aleksi Räsänen 2010
		        <aleksi.rasanen@runosydan.net>

		"Freedom is not worth having if it does not 
		 include the freedom to make mistakes."
		   - M. Gandhi
	*/
	// *******************************************
	class CUsers
	{
		//! CSQLite database class.
		private $db;

		//! Database table where user information is stored.
		private $users_table;

		//! Database field names will be stored here.
		private $table_fields = array();

		//! Password crypt method, sha1, md5 or something.
		private $pw_method;

		// *******************************************
		//	Class constructor
		/*!
			@brief Initialize class variables.

			@param $db CSQLite class instance.
		*/
		// *******************************************
		public function __construct( $db )
		{
			$this->db = $db;
			$this->users_table = 'users';
			$this->pw_method = 'sha1';

			$this->table_fields = array(
				'username' => 'username',
				'password' => 'password' );
		}

		// *******************************************
		//	setUsersTable
		/*!
			@brief Set table name where usernames and 
			  passwords should be found.

			@param $table Database table name
		*/
		// *******************************************
		public function setUsersTable( $table )
		{
			$this->users_table = $table;
		}

		// *******************************************
		//	setTableFields
		/*!
			@brief Set database table field names where
			  we are trying to look for username and password.
			  If this method is not called, we use default
			  values "username" and "password" as a field names.

			@param $fields Array where must can be two indexes.
			  Key names must be "username" and "password".
		*/
		// *******************************************
		public function setTableFields( $fields )
		{
			if( isset( $fields['username'] ) )
				$this->table_fields['username'] = $fields['username'];

			if( isset( $fields['password'] ) )
				$this->table_fields['password'] = $fields['password'];
		}

		// *******************************************
		//	setPasswordMethod
		/*!
			@brief Set password method (information how password
			  is stored in database).

			@param $method Method. Can only be sha1 or md5.
		*/
		// *******************************************
		public function setPasswordMethod( $method )
		{
			$method = strtolower( $method );

			if( $method == 'sha1' || $method == 'md5' )
				$this->pw_method = $method;
		}

		// *******************************************
		//	checkLogin
		/*!
			@brief Check if login was correct.

			@param $username Username

			@param $password Password

			@return -1 Invalid user, -2 Invalid password,
			  -3 Query failed. Possible reasons: invalid
			  users_table name or invalid fieldname in username
			  or password field. Assoc array if all was ok.
		*/
		// *******************************************
		public function checkLogin( $username, $password )
		{
			$tf = $this->table_fields;
			$username = $this->db->makeSafeForDb( $username );

			// Crypt given password
			if( $this->pw_method == 'sha1' )
				$password = sha1( $password );
			else if( $this->pw_method == 'md5' )
				$password = md5( $password );
			
			// Get all fields from users table.
			$q = 'SELECT * FROM ' . $this->users_table
				. ' WHERE ' . $tf['username'] . '="' 
				. $username . '"';

			$ret = $this->db->queryAndAssoc( $q );

			// -1 = No row found, eg. query was ok but no lines found.
			// -2 = Query failed. Reason might be that $tf['username']
			// is not correct fieldname or $users_table is incorrect.
			if( $ret == -1 )
				return -1;
			else if( $ret == -2 )
				return -3;

			// Make sure that there was field for password with
			// same name than we have in array $tf['password'].
			if(! isset( $ret[0][$tf['password']] ) )
				return -4;

			// Was password right or not.
			if( $ret[0][$tf['password']] == $password )
				return $ret;
			else
				return -2;
		}

		// *******************************************
		//	getUserById
		/*!
			@brief Get user infromation by user ID.

			@param $id ID-number

			@return Array if user found, otherwise -1.
		*/
		// *******************************************
		public function getUserById( $id )
		{
			$id = $this->db->makeSafeForDb( $id );
			$q = 'SELECT * FROM ' . $this->users_table 
				. ' WHERE id=' . $id;

			return $this->db->queryAndAssoc( $q );
		}

		// *******************************************
		//	getUserByUsername
		/*!
			@brief Get user information by username.

			@param $username Username

			@return Array if user found, otherwise -1.
		*/
		// *******************************************
		public function getUserByUsername( $username )
		{
			$username = $this->db->makeSafeForDb( $username );
			$q = 'SELECT * FROM ' . $this->users_table 
				. ' WHERE ' . $this->table_fields['username']
				. '="' . $username . '"';

			return $this->db->queryAndAssoc( $q );
		}

		// *******************************************
		//	registerNew
		/*!
			@brief Register new user

			@param $username Username

			@param $password Uncrypred password. We crypt
			  it in this function.

			@return True on success, -1 if user already exists.
		*/
		// *******************************************
		public function registerNew( $username, $password )
		{
			// Check that user does not exists already.
			$ret = $this->getUserByUsername( $username );

			if( is_array( $this->getUserByUsername( $username ) ) )
				return -1;

			// Crypt password if pw_method is md5 or sha1.
			if( $this->pw_method == 'sha1' )
				$password = sha1( $password );
			else if( $this->pw_method == 'md5' )
				$password = md5( $password );

			// Create query
			$q = 'INSERT INTO ' . $this->users_table . 
				' VALUES( NULL, "' . $username . '",'
				. '"' . $password . '",'
				. '"' . date( 'Y-m-d H:i:s' ) . '" );';

			$this->db->query( $q );

			return true;
		}
	}

?>
