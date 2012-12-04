function validateRegisterForm()
	{
	var unm=document.forms["register"]["user_name"].value;
	if (unm==null || unm=="")
	  {
	  alert("User name must be filled out");
	  return false;
	  }
	var pwd=document.forms["register"]["password"].value;
	if (pwd==null || pwd=="")
	  {
	  alert("User name must be filled out");
	  return false;
	  }
	var email=document.forms["register"]["user_email"].value;
	var atpos=email.indexOf("@");
	var dotpos=email.lastIndexOf(".");
	if (atpos<1 || dotpos<atpos+2 || dotpos+2>=email.length)
	  {
	  alert("Not a valid e-mail address");
	  return false;
	  }
}

function validateLoginForm()
{
		
	var uname=document.forms["login"]["username_login"].value;
	if (uname==null || uname=="")
	  {
	  alert("User name must be filled out");
	  return false;
	  }
	var pass=document.forms["login"]["password_login"].value;
	if (pass==null || pass=="")
	  {
	  alert("Password must be filled out");
	  return false;
	  }
}	