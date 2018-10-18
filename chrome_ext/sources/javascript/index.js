var accountTotal = 0;

window.onload = function () {
    if (typeof(Storage) !== "undefined") {
        // Code for localStorage/sessionStorage.
        var cashNodeUrl = window.localStorage['cash_node_url'];
        if (cashNodeUrl == null || cashNodeUrl == '') {
            window.localStorage['cash_node_urls'] = JSON.stringify([api_url]);
            window.localStorage['cash_node_url'] = api_url;
        }
        var passphrase = window.localStorage['cash_passphrase'];
        if (passphrase == null || passphrase == '') {
            window.location.href = '../../passphrase.html'
            return
        }
    } else {
        // Sorry! No Web Storage support..
        alert('Sorry! No Web Storage support')
        return
    }

    loadListAccount();

    document.getElementById("bt_import").onclick = function () {
        importAccount();
        return false;
    };
    document.getElementById("bt_new").onclick = function () {
        newAccount();
        return false;
    };
};

function loadListAccount() {
    showLoading(true);

    var xhr = new XMLHttpRequest();   // new HttpRequest instance
    xhr.open("POST", window.localStorage['cash_node_url']);
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xhr.onreadystatechange = function (oEvent) {

        showLoading(false);

        if (xhr.status == 200 && xhr.readyState == XMLHttpRequest.DONE) {

            var response = JSON.parse(this.responseText.toString());
            if (response.Result != null && response.Result != '') {
                var accounts = response.Result.Accounts;
                $('#walletName').text(response.Result.WalletName);
                removeChilds('list_account')
                accountTotal = 0;
                for (var key in accounts) {
                    var balance = accounts[key];
                    var li = document.createElement('li');
                    console.log(key)
                    li.innerHTML = '<a href="../../account_detail.html?account=' + key + '">' + key + ' (' + balance + ')' + '</a>'
                    li.classList = "list-group-item"
                    document.getElementById("list_account").appendChild(li);
                    accountTotal++;
                }
                document.getElementById("loader").style.display = "none";
                document.getElementById("myDiv").style.display = "block";
            } else {
                if (response.Error != null) {
                    alert(response.Error.message)
                } else {
                    alert('Bad response');
                }
            }
        }
    };
    xhr.send(JSON.stringify({
        jsonrpc: "1.0",
        method: "listaccounts",
        params: [],
        id: 1
    }));
}

function showLoading(show) {
    if (show) {
        document.getElementById("loader").style.display = "block";
        document.getElementById("myDiv").style.display = "none";
    } else {
        document.getElementById("loader").style.display = "none";
        document.getElementById("myDiv").style.display = "block";
    }
}

function newAccount() {
    var accName = 'Account ' + document.getElementById("txt_accountName").value;

    showLoading(true);

    var xhr = new XMLHttpRequest();   // new HttpRequest instance
    xhr.open("POST", window.localStorage['cash_node_url']);
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xhr.onreadystatechange = function (oEvent) {
        showLoading(false)
        if (xhr.status == 200 && xhr.readyState == XMLHttpRequest.DONE) {
            var response = JSON.parse(this.responseText.toString());
            if (response.Result != null && response.Result != '') {
                loadListAccount();
            } else {
                if (response.Error != null) {
                    alert(response.Error.message)
                } else {
                    alert('Bad response');
                }
            }
        }
    };
    xhr.send(JSON.stringify({
        jsonrpc: "1.0",
        method: "getaccountaddress",
        params: accName,
        id: 1
    }));
}

function importAccount() {

    var priKey = document.getElementById("txt_privateKey").value;
    var passphrase = window.localStorage['cash_passphrase'];
    var accName = 'Account ' + accountTotal;

    showLoading(true);

    var xhr = new XMLHttpRequest();   // new HttpRequest instance
    xhr.open("POST", window.localStorage['cash_node_url']);
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xhr.onreadystatechange = function (oEvent) {
        showLoading(false)
        if (xhr.status == 200 && xhr.readyState == XMLHttpRequest.DONE) {
            var response = JSON.parse(this.responseText.toString());
            if (response.Result != null && response.Result != '') {
                loadListAccount();
            } else {
                if (response.Error != null) {
                    alert(response.Error.message)
                } else {
                    alert('Bad response');
                }
            }
        }
    };
    xhr.send(JSON.stringify({
        jsonrpc: "1.0",
        method: "importaccount",
        params: [priKey, accName, passphrase],
        id: 1
    }));
}