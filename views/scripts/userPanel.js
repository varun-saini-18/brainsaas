function changeStatus(email) {
  console.log('changeStatus')
    var url = 'change/'+email
    fetch(url)
    .then(function (response) {
      if(document.getElementById(email).innerHTML.trim() == "Deactivate")
      {
        document.getElementById(email).innerHTML = "Activate";
        console.log('Changed')
      }
      else if(document.getElementById(email).innerHTML.trim() == "Activate")     
      {
        document.getElementById(email).innerHTML = "Deactivate";
      }
      else 
      {
        console.log('Else');
      }      
    })
}

function changePass(email) {
  
    var password = document.getElementById('change_pass').value;
    var conf_password = document.getElementById('conf_change_pass').value;
    console.log(password,conf_password);
    fetch('/changeUserPassword', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            
          email: email,
          password: password,
          password_2: conf_password
            
        })
    })
    .then(function (response) {
        location.reload();
    });
}
