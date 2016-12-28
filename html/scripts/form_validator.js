function ValidateInput(){  
    var IPformat = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
    var mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    
    var maildata = document.forms["user_config"]["dst_emails"].value;
    var vtdata = document.forms["user_config"]["vt_key"].value;
    
    // Check if all email addresses have the right format
    if(maildata != ""){
        var emails = maildata.split(',');
        var arrayLength = emails.length;
        
        for (var i=0; i<arrayLength;i++){
            email = emails[i].replace(/\s+/g, '');
            if(email.match(mailformat) === null){    
                alert("You have entered an invalid email address!");
                return false;
            }
        }
    }
    
    var BLdata = document.getElementById("blacklist").value;
    if (BLdata != ""){
        // Check if all blacklisted IP addresses have the right format
        var bad_ips = BLdata.split(',');
        var bipLength = bad_ips.length;
        
        for (var i=0; i<bipLength;i++){
            ip = bad_ips[i].replace(/\s+/g, '');
            if(ip.match(IPformat) === null){    
                alert("You have entered an invalid IP address in the blacklist!");
                return false;
            }
        }
    }
    var WLdata = document.getElementById("whitelist").value;
    if (WLdata != ""){
        // Check if all whitelisted IP addresses have the right format
        var good_ips = WLdata.split(',');
        var gipLength = good_ips.length;
        
        for (var i=0; i<gipLength;i++){
            ip = good_ips[i].replace(/\s+/g, '');
            if(ip.match(IPformat) === null){    
                alert("You have entered an invalid IP address in the whitelist!");
                return false;
            }
        }
    }
    // Check if there is overlapping between blacklist and whitelist
    for (var i=0; i<gipLength;i++){
        gip = good_ips[i].replace(/\s+/g, '');
        for (var j=0; j<bipLength;j++){
            bip = bad_ips[j].replace(/\s+/g, '');
            if (gip == bip){
                alert("The IP " + gip + " appears in both the blacklist and the whitelist!");
                return false;
            }
        }
    }

    return true;

}
