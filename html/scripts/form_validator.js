function ValidateIPaddress(ip){  
	//var ipformat = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
	var ipformat = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;
	if(ip.match(ipformat)){  
		return true;  
	}else{  
		alert(ip + " is not valid IP address!");  
		return false;  
	}  
}

function ValidateDomain(domain) { 
    var validDomain = /^((?:(?:(?:\w[\.\-\+]?)*)\w)+)((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$/;
	if(domain.match(validDomain)){
		return True;
	}else{
		alert(domain + " is not valid domain!");
		return false;
	}
}

function ValidateInput() {

    var IPformat = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
    var mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
	var domainformat = /^((?:(?:(?:\w[\.\-\+]?)*)\w)+)((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$/;
	var isIP = /^[^a-z]*[0-9]+[^a-z]*$/;
	var isDomain = /^[a-zA-Z0-9]{1,70}.[a-zA-Z0-9]{1,20}$/;
    
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

/*    
    var BLdata = document.getElementById("blacklist").value;
    if (BLdata != ""){
        // Check if all blacklisted IP addresses have the right format
        var bad_ips = BLdata.split(',');
        var bipLength = bad_ips.length;
        
        for (var i=0; i<bipLength;i++){
            ip = bad_ips[i].replace(/\s+/g, '');
            if(ip.match(IPformat) === null){
                alert("You have entered an invalid IP address or domain in the blacklist!");
                return false;
            }
        }
    }
*/
	// Check if all blacklisted domains and IPs have the right format
	var BLdata = document.getElementById("blacklist").value;		
	if (BLdata != ""){
		var bad_ips = BLdata.split(',');
		var bipLength = bad_ips.length;
		
		for (var i=0; i<bipLength;i++){
			var entry = bad_ips[i].replace(/\s+/g, '');
			if(entry.match(isDomain)){
				if(ValidateDomain(entry)){
					var result = "";
				}else{
					var result = "false";
				}
			}else if(entry.match(isIP)){				
				if(ValidateIPaddress(entry)){
					var result = "";
				}else{
					var result = "false";
				}
			}else{
				alert("Something is wrong here!")
			}
		}
		if(result == ""){
			console.log("All good! Checking if entry is present in Whitelist!")
		}else{
			return false;
		}
	}	
		
/*		
    var WLdata = document.getElementById("whitelist").value;
    if (WLdata != ""){
        // Check if all whitelisted IP addresses have the right format
        var good_ips = WLdata.split(',');
        var gipLength = good_ips.length;
        
        for (var i=0; i<gipLength;i++){
            var ip = good_ips[i].replace(/\s+/g, '');
            if(ip.match(IPformat) === null){    
                alert("You have entered an invalid IP address in the whitelist!");
                return false;
            }
        }
    }
*/
	// Check if all whitelisted domains and IPs have the right format
    var WLdata = document.getElementById("whitelist").value;
    if (WLdata != ""){
		var good_ips = WLdata.split(',');
		var gipLength = good_ips.length;
		
		for (var i=0; i<gipLength;i++){
			var entry = good_ips[i].replace(/\s+/g, '');
			if(entry.match(isDomain)){
				if(ValidateDomain(entry)){
					var result = "";
				}else{
					var result = "false";
				}
			}else if(entry.match(isIP)){				
				if(ValidateIPaddress(entry)){
					var result = "";
				}else{
					var result = "false";
				}
			}
		}
		if(result == ""){
			console.log("All good! Checking if entry is present in Blacklist!")
		}else{
			return false;
		}
	}	
	
    // Check if there is overlapping between blacklist and whitelist entries
    for (var i=0; i<gipLength;i++){
        gip = good_ips[i].replace(/\s+/g, '');
        for (var j=0; j<bipLength;j++){
            var bip = bad_ips[j].replace(/\s+/g, '');
            if (gip == bip){
                alert("The " + gip + " appears in both the blacklist and the whitelist!");
                return false;
            }
        }
    }

    return true;

}

function ValidateMailerInput(){
    var mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    var selector = document.forms["from_email"]["selector"].value;
    var mailerdata = document.forms["from_email"]["mailer_address"].value;
    var pwddata = document.forms["from_email"]["mailer_pwd"].value;
    
    if (selector === 'gmail'){
        if(mailerdata != ""){
            mailerdata = mailerdata.replace(/\s+/g, '');
            if(mailerdata.match(mailformat) === null){    
                alert("You have entered an invalid email address!");
                return false;
            }
        }else{
            alert("You did not entered the email address!");
            return false;
        }
    
        if(pwddata == ""){
            alert("You entered an empty password!");
            return false;
        }
    }
    
    return true;
}
