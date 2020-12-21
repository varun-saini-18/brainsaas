// To specify the starting index
var start = -1; 

function myFunc() {
    var email = document.getElementById('search_state').value;
    window.location.href = "http://localhost:3000/user_panel/"+email;
}

// This function is called to load initial users when the page loads.
func();

function func() {
    start=start+1;
    var url = '/users_list/'+start;
    fetch(url)
        .then(function (response) {
        return response.json();
    })
    .then(function (data) {
        const users = data.users;
        console.log(users);
        for(var i=0;i<users.length;i++)
        {
            var url = 'href="/user_panel/'+users[i].email + '"'
            $('#dynamic_list').append(' <div class="card"><a class="link"' + url +'><div class="center"><h2>'+users[i].name+'</h2></div></a></div><br>');
        }
    })
}

var working = false;
console.log('Yes')

// This function gets call whenever scrollbar touches bottom
$(window).scroll(function() {
    if ($(this).scrollTop() + 1 >= $('body').height() - $(window).height()) {
        if (working == false) {
            working = true;
            start=start+1;
            console.log(start*4+22)
            var url = '/users_list/'+start;
            fetch(url)
            .then(function (response) {
                return response.json();
            })
            .then(function (data) {
                const users = data.users;
                console.log(users);
                for(var i=0;i<users.length;i++)
                {
                    var url = 'href="/user_panel/'+users[i].email + '"'
                    $('#dynamic_list').append(' <div class="card"><a class="link"' + url +'><div class="center"><h2>'+users[i].name+'</h2></div></a></div><br>');
                }
                
            })
            setTimeout(function() {
                working = false;
            }, 100)
        }
    }
})